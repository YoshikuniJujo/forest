{-# LANGUAGE PackageImports, OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module TlsIo (
	TlsIo, evalTlsIo, liftIO, throwError, readCached, randomByteString,
	Partner(..), opponent, isCiphered,

	readContentType, writeContentType, readVersion, writeVersion,
	readLen, writeLen, 

	setVersion, setClientRandom, setServerRandom,
	cacheCipherSuite, flushCipherSuite,
	
	encryptRSA, generateKeys, updateHash, finishedHash, clientVerifySign,

	encryptMessage, decryptMessage,
	updateSequenceNumber, updateSequenceNumberSmart,
) where

import Prelude hiding (read)

import System.IO
import Control.Applicative
import "monads-tf" Control.Monad.Error
import "monads-tf" Control.Monad.State
import Data.Word
import qualified Data.ByteString as BS
import "crypto-random" Crypto.Random
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.PubKey.HashDescr as RSA
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA

import qualified CryptoTools as CT
import Basic

type TlsIo cnt = ErrorT String (StateT (TlsClientState cnt) IO)

data TlsClientState cnt = TlsClientState {
	tlssHandle			:: Handle,
	tlssContentCache		:: [cnt],

	tlssVersion			:: Maybe CT.MSVersion,
	tlssClientWriteCipherSuite	:: CipherSuite,
	tlssServerWriteCipherSuite	:: CipherSuite,
	tlssCachedCipherSuite		:: CipherSuite,

	tlssMasterSecret		:: Maybe BS.ByteString,
	tlssClientRandom		:: Maybe BS.ByteString,
	tlssServerRandom		:: Maybe BS.ByteString,
	tlssClientWriteMacKey		:: Maybe BS.ByteString,
	tlssServerWriteMacKey		:: Maybe BS.ByteString,
	tlssClientWriteKey		:: Maybe BS.ByteString,
	tlssServerWriteKey		:: Maybe BS.ByteString,

	tlssRandomGen			:: SystemRNG,
	tlssSha256Ctx			:: SHA256.Ctx,
	tlssClientSequenceNumber	:: Word64,
	tlssServerSequenceNumber	:: Word64
 }

initTlsClientState :: EntropyPool -> Handle -> TlsClientState cnt
initTlsClientState ep sv = TlsClientState {
	tlssHandle			= sv,
	tlssContentCache		= [],

	tlssVersion			= Nothing,
	tlssClientWriteCipherSuite	= TLS_NULL_WITH_NULL_NULL,
	tlssServerWriteCipherSuite	= TLS_NULL_WITH_NULL_NULL,
	tlssCachedCipherSuite		= TLS_NULL_WITH_NULL_NULL,

	tlssMasterSecret		= Nothing,
	tlssClientRandom		= Nothing,
	tlssServerRandom		= Nothing,
	tlssClientWriteMacKey		= Nothing,
	tlssServerWriteMacKey		= Nothing,
	tlssClientWriteKey		= Nothing,
	tlssServerWriteKey		= Nothing,

	tlssRandomGen			= cprgCreate ep,
	tlssSha256Ctx			= SHA256.init,
	tlssClientSequenceNumber	= 0,
	tlssServerSequenceNumber	= 0
 }

evalTlsIo :: TlsIo cnt a -> EntropyPool -> Handle -> IO a
evalTlsIo io ep sv = do
	ret <- runErrorT io `evalStateT` initTlsClientState ep sv
	case ret of
		Right r -> return r
		Left err -> error err

readCached :: TlsIo cnt [cnt] -> TlsIo cnt cnt
readCached rd = do
	tlss@TlsClientState{ tlssContentCache = cch } <- get
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
	(r, gen) <- cprgGenerate len <$> gets tlssRandomGen
	tlss <- get
	put tlss{ tlssRandomGen = gen }
	return r

data Partner = Server | Client deriving (Show, Eq)

opponent :: Partner -> Partner
opponent Server = Client
opponent Client = Server

isCiphered :: Partner -> TlsIo cnt Bool
isCiphered partner = (/= TLS_NULL_WITH_NULL_NULL) <$> gets (case partner of
	Client -> tlssClientWriteCipherSuite
	Server -> tlssServerWriteCipherSuite)

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
	r <- liftIO . flip BS.hGet n =<< gets tlssHandle
	if BS.length r == n then return r else throwError $
		"Basic.read:\n" ++
			"\tactual  : " ++ show n ++ "byte\n" ++
			"\texpected: " ++ show (BS.length r) ++ "byte\n"

write :: BS.ByteString -> TlsIo cnt ()
write dat = liftIO . flip BS.hPut dat =<< gets tlssHandle

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
	put $ tlss { tlssCachedCipherSuite = cs }

flushCipherSuite :: Partner -> TlsIo cnt ()
flushCipherSuite p = do
	tlss <- get
	case p of
		Client -> put tlss {
			tlssClientWriteCipherSuite = tlssCachedCipherSuite tlss }
		Server -> put tlss {
			tlssServerWriteCipherSuite = tlssCachedCipherSuite tlss }

encryptRSA :: RSA.PublicKey -> BS.ByteString -> TlsIo cnt BS.ByteString
encryptRSA pub pln = do
	g <- gets tlssRandomGen
	let (Right e, g') = RSA.encrypt g pub pln
	tlss <- get
	put tlss { tlssRandomGen = g' }
	return e

generateKeys :: BS.ByteString -> TlsIo cnt ()
generateKeys pms = do
	mv <- gets tlssVersion
	mcr <- gets $ (CT.ClientRandom <$>) . tlssClientRandom
	msr <- gets $ (CT.ServerRandom <$>) . tlssServerRandom
	case (mv, mcr, msr) of
		(Just v, Just cr, Just sr) -> do
			let	ms = CT.generateMasterSecret v pms cr sr
				ems = CT.generateKeyBlock v cr sr ms 72
				[cwmk, swmk, cwk, swk] =
					divide [ 20, 20, 16, 16 ] ems
			tlss <- get
			put $ tlss {
				tlssMasterSecret = Just ms,
				tlssClientWriteMacKey = Just cwmk,
				tlssServerWriteMacKey = Just swmk,
				tlssClientWriteKey = Just cwk,
				tlssServerWriteKey = Just swk }
		_ -> throwError "No version / No (client/server) random"
	where
	divide [] _ = []
	divide (n : ns) bs
		| bs == BS.empty = []
		| otherwise = let (x, xs) = BS.splitAt n bs in x : divide ns xs

updateHash :: BS.ByteString -> TlsIo cnt ()
updateHash bs = do
	tlss@TlsClientState{ tlssSha256Ctx = sha256 } <- get
	put tlss { tlssSha256Ctx = SHA256.update sha256 bs }

finishedHash :: Partner -> TlsIo cnt BS.ByteString
finishedHash partner = do
	mms <- gets tlssMasterSecret
	sha256 <- SHA256.finalize <$> gets tlssSha256Ctx
	mv <- gets tlssVersion
	case (mv, mms) of
		(Just CT.TLS12, Just ms) -> return $ case partner of
			Client -> CT.generateFinished CT.TLS12 True ms sha256
			Server -> CT.generateFinished CT.TLS12 False ms sha256
		_ -> throwError "finishedHash: No version / No master secrets"

clientVerifySign :: RSA.PrivateKey -> TlsIo cnt BS.ByteString
clientVerifySign pkys = do
	sha256 <- gets $ SHA256.finalize . tlssSha256Ctx
	let Right hashed = RSA.padSignature
		(RSA.public_size $ RSA.private_pub pkys)
		(RSA.digestToASN1 RSA.hashDescrSHA256 sha256)
	return $ RSA.dp Nothing pkys hashed

encryptMessage :: Partner ->
	ContentType -> Version -> BS.ByteString -> TlsIo cnt BS.ByteString
encryptMessage partner ct v msg = do
	version <- gets tlssVersion
	cs <- cipherSuite partner
	mwk <- writeKey partner
	sn <- sequenceNumber partner
	mmk <- macKey partner
	gen <- gets tlssRandomGen
	case (version, cs, mwk, mmk) of
		(Just CT.TLS12, TLS_RSA_WITH_AES_128_CBC_SHA, Just wk, Just mk)
			-> do	let (ret, gen') =
					CT.encryptMessage gen wk sn mk ct v msg
				tlss <- get
				put tlss{ tlssRandomGen = gen' }
				return ret
		(_, TLS_NULL_WITH_NULL_NULL, _, _) -> return msg
		_ -> throwError $ "encrypt:\n" ++
			"\tNo keys or not implemented cipher suite"

decryptMessage :: Partner ->
	ContentType -> Version -> BS.ByteString -> TlsIo cnt BS.ByteString
decryptMessage partner ct v enc = do
	version <- gets tlssVersion
	cs <- cipherSuite partner
	mwk <- writeKey partner
	sn <- sequenceNumber partner
	mmk <- macKey partner
	case (version, cs, mwk, mmk) of
		(Just CT.TLS12, TLS_RSA_WITH_AES_128_CBC_SHA, Just key, Just mk)
			-> do	let emsg = CT.decryptMessage key sn mk ct v enc
				case emsg of
					Right msg -> return msg
					Left err -> throwError err
		(_, TLS_NULL_WITH_NULL_NULL, _, _) -> return enc
		_ -> throwError "clientWriteDecrypt: No keys or Bad cipher suite"

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

sequenceNumber :: Partner -> TlsIo cnt Word64
sequenceNumber partner = gets $ case partner of
	Client -> tlssClientSequenceNumber
	Server -> tlssServerSequenceNumber

updateSequenceNumber :: Partner -> TlsIo cnt ()
updateSequenceNumber partner = do
	sn <- gets $ case partner of
		Client -> tlssClientSequenceNumber
		Server -> tlssServerSequenceNumber
	tlss <- get
	put $ case partner of
		Client -> tlss { tlssClientSequenceNumber = succ sn }
		Server -> tlss { tlssServerSequenceNumber = succ sn }

updateSequenceNumberSmart :: Partner -> TlsIo cnt ()
updateSequenceNumberSmart partner =
	flip when (updateSequenceNumber partner) =<< isCiphered partner
