{-# LANGUAGE PackageImports, OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module TlsIo (
	TlsIo, evalTlsIo, liftIO, throwError, readCached, randomByteString,
	Partner(..),

	readContentType, writeContentType, readVersion, writeVersion,
	readLen, writeLen,

	setVersion, setClientRandom, setServerRandom,
	cacheCipherSuite, flushCipherSuite,

	decryptRSA, generateKeys, updateHash, finishedHash, clientVerifyHash,

	encryptMessage, decryptMessage,
	updateSequenceNumber,
) where

import Prelude hiding (read)

import Control.Applicative
import "monads-tf" Control.Monad.Error
import "monads-tf" Control.Monad.State
import Data.Word
import qualified Data.ByteString as BS
import System.IO
import "crypto-random" Crypto.Random
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.PubKey.HashDescr as RSA
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA

-- import qualified MasterSecret as MS
import qualified CryptoTools as CT
import Basic

type TlsIo cnt = ErrorT String (StateT (TlsState cnt) IO)

data TlsState cnt = TlsState {
	tlssClientHandle :: Handle,
	tlssContentCache :: [cnt],

	tlssVersion :: Maybe CT.MSVersion,
	tlssPrivateKey :: RSA.PrivateKey,
	tlssClientWriteCipherSuite :: CipherSuite,
	tlssServerWriteCipherSuite :: CipherSuite,
	tlssCachedCipherSuite :: Maybe CipherSuite,

	tlssClientRandom :: Maybe BS.ByteString,
	tlssServerRandom :: Maybe BS.ByteString,
	tlssMasterSecret :: Maybe BS.ByteString,
	tlssClientWriteMacKey :: Maybe BS.ByteString,
	tlssServerWriteMacKey :: Maybe BS.ByteString,
	tlssClientWriteKey :: Maybe BS.ByteString,
	tlssServerWriteKey :: Maybe BS.ByteString,

	tlssRandomGen :: SystemRNG,
	tlssSha256Ctx :: SHA256.Ctx,
	tlssClientSequenceNumber :: Word64,
	tlssServerSequenceNumber :: Word64
 }

initTlsState :: EntropyPool -> Handle -> RSA.PrivateKey -> TlsState cnt
initTlsState ep cl pk = TlsState {
	tlssClientHandle = cl,
	tlssContentCache = [],

	tlssVersion = Nothing,
	tlssPrivateKey = pk,
	tlssClientWriteCipherSuite = TLS_NULL_WITH_NULL_NULL,
	tlssServerWriteCipherSuite = TLS_NULL_WITH_NULL_NULL,
	tlssCachedCipherSuite = Nothing,

	tlssClientRandom = Nothing,
	tlssServerRandom = Nothing,
	tlssMasterSecret = Nothing,
	tlssClientWriteMacKey = Nothing,
	tlssServerWriteMacKey = Nothing,
	tlssClientWriteKey = Nothing,
	tlssServerWriteKey = Nothing,

	tlssRandomGen = cprgCreate ep,
	tlssSha256Ctx = SHA256.init,
	tlssClientSequenceNumber = 0,
	tlssServerSequenceNumber = 0
 }

evalTlsIo :: TlsIo cnt a -> EntropyPool -> Handle -> RSA.PrivateKey -> IO a
evalTlsIo io ep cl pk = do
	ret <- runErrorT io `evalStateT` initTlsState ep cl pk
	case ret of
		Right r -> return r
		Left err -> error err

readCached :: TlsIo cnt [cnt] -> TlsIo cnt cnt
readCached rd = do
	tlss@TlsState{ tlssContentCache = cch } <- get
	case cch of
		[] -> do
			r : cch' <- rd
			put tlss { tlssContentCache = cch' }
			return r
		r : cch' -> do
			put tlss { tlssContentCache = cch' }
			return r

randomByteString :: Int -> TlsIo cnt BS.ByteString
randomByteString len = do
	tlss@TlsState{ tlssRandomGen = gen } <- get
	let (r, gen') = cprgGenerate len gen
	put tlss { tlssRandomGen = gen' }
	return r

data Partner = Server | Client deriving (Show, Eq)

readContentType :: TlsIo cnt ContentType
readContentType = byteStringToContentType <$> read 1

writeContentType :: ContentType -> TlsIo cnt ()
writeContentType = write . contentTypeToByteString

readVersion :: TlsIo cnt Version
readVersion = byteStringToVersion <$> read 2

writeVersion :: Version -> TlsIo cnt ()
writeVersion = write . versionToByteString

readLen :: Int -> TlsIo cnt BS.ByteString
readLen n = read . byteStringToInt =<< read n

writeLen :: Int -> BS.ByteString -> TlsIo cnt ()
writeLen n bs = write (intToByteString n $ BS.length bs) >> write bs

read :: Int -> TlsIo cnt BS.ByteString
read n = do
	r <- liftIO . flip BS.hGet n =<< gets tlssClientHandle
	if BS.length r == n
		then return r
		else throwError $ "Basic.read: bad reading: " ++
			show (BS.length r) ++ " " ++ show n

write :: BS.ByteString -> TlsIo cnt ()
write dat = liftIO . flip BS.hPut dat =<< gets tlssClientHandle

setVersion :: Version -> TlsIo cnt ()
setVersion v = do
	tlss <- get
	case CT.versionToVersion v of
		Just v' -> put tlss { tlssVersion = Just v' }
		_ -> throwError "setVersion: Not implemented"

setClientRandom, setServerRandom :: Random -> TlsIo cnt ()
setClientRandom (Random cr) = do
	tlss <- get
	put $ tlss { tlssClientRandom = Just cr }
setServerRandom (Random sr) = do
	tlss <- get
	put $ tlss { tlssServerRandom = Just sr }

cacheCipherSuite :: CipherSuite -> TlsIo cnt ()
cacheCipherSuite cs = do
	tlss <- get
	put $ tlss { tlssCachedCipherSuite = Just cs }

flushCipherSuite :: Partner -> TlsIo cnt ()
flushCipherSuite p = do
	tlss <- get
	case tlssCachedCipherSuite tlss of
		Just cs -> case p of
			Client -> put tlss { tlssClientWriteCipherSuite = cs }
			Server -> put tlss { tlssServerWriteCipherSuite = cs }
		_ -> throwError "No cached cipher suites"

decryptRSA :: BS.ByteString -> TlsIo cnt BS.ByteString
decryptRSA e = do
	pk <- gets tlssPrivateKey
	case RSA.decrypt Nothing pk e of
		Right d -> return d
		Left err -> throwError $ show err

generateKeys :: BS.ByteString -> TlsIo cnt ()
generateKeys pms = do
	tlss@TlsState{
		tlssVersion = mv,
		tlssClientRandom = mcr,
		tlssServerRandom = msr } <- get
	case (mv, CT.ClientRandom <$> mcr, CT.ServerRandom <$> msr) of
		(Just v, Just cr, Just sr) -> do
			let	ms = CT.generateMasterSecret v pms cr sr
				ems = CT.generateKeyBlock v cr sr ms 72
				[cwmk, swmk, cwk, swk] = divide [20, 20, 16, 16] ems
			put $ tlss {
				tlssMasterSecret = Just ms,
				tlssClientWriteMacKey = Just cwmk,
				tlssServerWriteMacKey = Just swmk,
				tlssClientWriteKey = Just cwk,
				tlssServerWriteKey = Just swk }
		_ -> throwError "No client random / No server random"
	where
	divide [] _ = []
	divide (n : ns) bs
		| bs == BS.empty = []
		| otherwise = let (x, xs) = BS.splitAt n bs in x : divide ns xs

updateHash :: BS.ByteString -> TlsIo cnt ()
updateHash bs = do
	tlss@TlsState{ tlssSha256Ctx = sha256 } <- get
	put tlss { tlssSha256Ctx = SHA256.update sha256 bs }

finishedHash :: Partner -> TlsIo cnt BS.ByteString
finishedHash partner = do
	mms <- gets tlssMasterSecret
	sha256 <- SHA256.finalize <$> gets tlssSha256Ctx
	mv <- gets tlssVersion
	case (mv, mms) of
		(Just CT.TLS12, Just ms) -> return $
			CT.generateFinished CT.TLS12 (partner == Client) ms sha256
		_ -> throwError "No master secrets"

clientVerifyHash :: RSA.PublicKey -> TlsIo cnt BS.ByteString
clientVerifyHash pub = do
	sha256 <- gets $ SHA256.finalize . tlssSha256Ctx
	let Right hashed = RSA.padSignature (RSA.public_size pub) $
		RSA.digestToASN1 RSA.hashDescrSHA256 sha256
	return hashed

encryptMessage :: ContentType -> Version -> BS.ByteString -> TlsIo cnt BS.ByteString
encryptMessage ct v msg = do
	version <- gets tlssVersion
	cs <- cipherSuite Server
	mwk <- writeKey Server
	sn <- sequenceNumber Server
	updateSequenceNumber Server
	mmk <- macKey Server
	gen <- gets tlssRandomGen
	case (version, cs, mwk, mmk) of
		(Just CT.TLS12, TLS_RSA_WITH_AES_128_CBC_SHA, Just wk, Just mk)
			-> do	let (ret, gen') =
					CT.encryptMessage gen wk sn mk ct v msg
				tlss <- get
				put tlss{ tlssRandomGen = gen' }
				return ret
		(_, TLS_NULL_WITH_NULL_NULL, _, _) -> return msg
		_ -> throwError $ "encryptMessage:\n" ++
			"\bNo keys or not implemented cipher suite"

decryptMessage :: ContentType -> Version -> BS.ByteString -> TlsIo cnt BS.ByteString
decryptMessage ct v enc = do
	version <- gets tlssVersion
	cs <- cipherSuite Client
	mwk <- writeKey Client
	sn <- sequenceNumber Client
	mmk <- macKey Client
	case (version, cs, mwk, mmk) of
		(Just CT.TLS12, TLS_RSA_WITH_AES_128_CBC_SHA, Just key, Just mk)
			-> do	let emsg = CT.decryptMessage key sn mk ct v enc
				case emsg of
					Right msg -> return msg
					Left err -> throwError err
		(_, TLS_NULL_WITH_NULL_NULL, _, _) -> return enc
		_ -> throwError "decryptMessage: No keys or bad cipher suite"

sequenceNumber :: Partner -> TlsIo cnt Word64
sequenceNumber partner = gets $ case partner of
		Client -> tlssClientSequenceNumber
		Server -> tlssServerSequenceNumber

updateSequenceNumber :: Partner -> TlsIo cnt ()
updateSequenceNumber partner = do
	cs <- gets $ case partner of
		Client -> tlssClientWriteCipherSuite
		Server -> tlssServerWriteCipherSuite
	sn <- gets $ case partner of
		Client -> tlssClientSequenceNumber
		Server -> tlssServerSequenceNumber
	tlss <- get
	case cs of
		TLS_RSA_WITH_AES_128_CBC_SHA -> put $ case partner of
			Client -> tlss { tlssClientSequenceNumber = succ sn }
			Server -> tlss { tlssServerSequenceNumber = succ sn }
		TLS_NULL_WITH_NULL_NULL -> return ()
		_ -> throwError "not implemented"

cipherSuite :: Partner -> TlsIo cnt CipherSuite
cipherSuite partner = gets $ case partner of
	Client -> tlssClientWriteCipherSuite
	Server -> tlssServerWriteCipherSuite

writeKey :: Partner -> TlsIo cnt (Maybe BS.ByteString)
writeKey partner = gets $ case partner of
	Client -> tlssClientWriteKey
	Server -> tlssServerWriteKey

macKey :: Partner -> TlsIo cnt (Maybe BS.ByteString)
macKey partner = gets $ case partner of
	Client -> tlssClientWriteMacKey
	Server -> tlssServerWriteMacKey
