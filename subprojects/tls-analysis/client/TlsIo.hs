{-# LANGUAGE PackageImports, OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module TlsIo (
	TlsIo, runTlsIo, evalTlsIo, initTlsState, liftIO,
	Partner(..), opponent, ServerHandle(..), ClientHandle(..),
	read, write, readLen, writeLen,

	readCached,

	clientWriteMacKey,

	setClientRandom, setServerRandom, setVersion,
	cacheCipherSuite, flushCipherSuite,
	generateMasterSecret,

	decrypt, encrypt, takeBodyMac,
	encryptRSA,

	debugShowKeys,

	Handle, Word8, ByteString, BS.unpack, BS.pack, throwError,

	updateHash, finishedHash, calcMac, updateSequenceNumber,
	updateSequenceNumberSmart,

	ContentType(..), readContentType, writeContentType,
	Version, readVersion, writeVersion,

	getCipherSuite, CipherSuite(..), showRandom,

	handshakeMessages, randomByteString,
) where

import Prelude hiding (read)

import Control.Applicative

import System.IO
import "monads-tf" Control.Monad.Error
import "monads-tf" Control.Monad.State

import Data.Word
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

import Crypto.PubKey.RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import Crypto.Cipher.AES

import qualified MasterSecret as MS
import Basic

import qualified Crypto.Hash.MD5 as MD5
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA256 as SHA256

import "crypto-random" Crypto.Random

type TlsIo cnt = ErrorT String (StateT (TlsState cnt) IO)

data TlsState cnt = TlsState {
	tlssVersion :: Maybe MS.MSVersion,
	tlssServerHandle :: Handle,
	tlssClientWriteCipherSuite :: CipherSuite,
	tlssServerWriteCipherSuite :: CipherSuite,
	tlssCachedCipherSuite :: Maybe CipherSuite,
	tlssClientRandom :: Maybe ByteString,
	tlssServerRandom :: Maybe ByteString,
	tlssMasterSecret :: Maybe ByteString,
	tlssClientWriteMacKey :: Maybe ByteString,
	tlssServerWriteMacKey :: Maybe ByteString,
	tlssClientWriteKey :: Maybe ByteString,
	tlssServerWriteKey :: Maybe ByteString,
	tlssSha256Ctx :: SHA256.Ctx,
	tlssHandshakeMessages :: ByteString,
	tlssClientSequenceNumber :: Word64,
	tlssServerSequenceNumber :: Word64,
	tlssRandomGen :: SystemRNG,
	tlssContentCacheClient :: [cnt],
	tlssContentCacheServer :: [cnt]
 } deriving Show

instance Show SystemRNG where
	show _ = "System Random Generator"

readCached :: Partner -> TlsIo cnt [cnt] -> TlsIo cnt cnt
readCached partner rd = do
	cch <- gets $ case partner of
		Client -> tlssContentCacheClient
		Server -> tlssContentCacheServer
	tlss <- get
	case cch of
		[] -> do
			r : cch' <- rd
			case partner of
				Client -> put tlss { tlssContentCacheClient = cch' }
				Server -> put tlss { tlssContentCacheServer = cch' }
			return r
		r : cch' -> do
			case partner of
				Client -> put tlss { tlssContentCacheClient = cch' }
				Server -> put tlss { tlssContentCacheServer = cch' }
			return r

setVersion :: MS.Version -> TlsIo cnt ()
setVersion v = do
	tlss <- get
	case MS.versionToVersion v of
		Just v' -> put tlss { tlssVersion = Just v' }
		_ -> throwError "setVersion: Not implemented"

instance Show MD5.Ctx where
	show = show . MD5.finalize

instance Show SHA1.Ctx where
	show = show . SHA1.finalize

instance Show SHA256.Ctx where
	show = show . SHA256.finalize

data ServerHandle = ServerHandle Handle deriving Show
data ClientHandle = ClientHandle Handle deriving Show

initTlsState :: EntropyPool -> ServerHandle -> TlsState cnt
initTlsState ep (ServerHandle sv) = TlsState {
	tlssVersion = Nothing,
	tlssServerHandle = sv,
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
	tlssSha256Ctx = SHA256.init,
	tlssClientSequenceNumber = 0,
	tlssServerSequenceNumber = 0,
	tlssRandomGen = cprgCreate ep,
	tlssHandshakeMessages = "",
	tlssContentCacheClient = [],
	tlssContentCacheServer = []
 }

data Partner = Server | Client deriving (Show, Eq)

opponent :: Partner -> Partner
opponent Server = Client
opponent Client = Server

handle :: Partner -> TlsState cnt -> Handle
handle Server = tlssServerHandle
handle _ = error "No Client Handle"

runTlsIo :: TlsIo cnt a -> TlsState cnt -> IO (Either String a, TlsState cnt)
runTlsIo io ts = runErrorT io `runStateT` ts

evalTlsIo :: TlsIo cnt a -> EntropyPool -> ServerHandle -> IO a
evalTlsIo io ep sv = do
	ret <- runErrorT io `evalStateT` initTlsState ep sv
	case ret of
		Right r -> return r
		Left err -> error err

read :: Partner -> Int -> TlsIo cnt ByteString
read partner n = do
	h <- gets $ handle partner
	r <- liftIO $ BS.hGet h n
	if BS.length r == n
		then return r
		else throwError $ "Basic.read: bad reading: " ++
			show (BS.length r) ++ " " ++ show n

write :: Partner -> ByteString -> TlsIo cnt ()
write partner dat = do
	h <- gets $ handle partner
	liftIO $ BS.hPut h dat

readLen :: Partner -> Int -> TlsIo cnt ByteString
readLen partner n = do
	len <- read partner n
	read partner $ byteStringToInt len

writeLen :: Partner -> Int -> ByteString -> TlsIo cnt ()
writeLen partner n bs = do
	write partner . intToByteString n $ BS.length bs
	write partner bs

encryptRSA :: PublicKey -> ByteString -> TlsIo cnt ByteString
encryptRSA pub pln = do
	g <- gets tlssRandomGen
	tlss <- get
	let (Right e, g') = RSA.encrypt g pub pln
	put tlss { tlssRandomGen = g' }
	return e

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

generateMasterSecret :: ByteString -> TlsIo cnt ()
generateMasterSecret pms = do
	mv <- gets tlssVersion
	mcr <- gets $ (MS.ClientRandom <$>) . tlssClientRandom
	msr <- gets $ (MS.ServerRandom <$>) . tlssServerRandom
	case (mv, mcr, msr) of
		(Just v, Just cr, Just sr) -> do
			let	ms = MS.generateMasterSecret v pms cr sr
				ems = MS.generateKeyBlock v cr sr ms 104
				[cwmk, swmk, cwk, swk] =
					divide [ 20, 20, 16, 16 ] ems
			tlss <- get
			put $ tlss {
				tlssMasterSecret = Just ms,
				tlssClientWriteMacKey = Just cwmk,
				tlssServerWriteMacKey = Just swmk,
				tlssClientWriteKey = Just cwk,
				tlssServerWriteKey = Just swk
			 }
		_ -> throwError "No client random / No server random"

divide :: [Int] -> BS.ByteString -> [BS.ByteString]
divide [] _ = []
divide (n : ns) bs
	| bs == BS.empty = []
	| otherwise = let (x, xs) = BS.splitAt n bs in x : divide ns xs

debugShowKeys :: TlsIo cnt [String]
debugShowKeys = do
	Just cwmk <- gets tlssClientWriteMacKey
	Just swmk <- gets tlssServerWriteMacKey
	Just cwk <- gets tlssClientWriteKey
	Just swk <- gets tlssServerWriteKey
	return [
		"### GENERATED KEYS ###",
		"ClntWr MAC Key: " ++ showKeySingle cwmk,
		"SrvrWr MAC Key: " ++ showKeySingle swmk,
		"ClntWr Key    : " ++ showKeySingle cwk,
		"SrvrWr Key    : " ++ showKeySingle swk ]

decrypt :: Partner -> ByteString -> TlsIo cnt ByteString
decrypt partner e = do
	version <- gets tlssVersion
	set <- getCipherSet partner
	case (version, set) of
		(Just MS.TLS12, (TLS_RSA_WITH_AES_128_CBC_SHA, Just key)) -> do
			let d = decryptCBC (initAES key)
				(BS.take 16 e) (BS.drop 16 e)
			return d
		(_, (TLS_NULL_WITH_NULL_NULL, _)) -> return e
		_ -> throwError "clientWriteDecrypt: No keys or Bad cipher suite"

encrypt :: Partner -> ByteString -> TlsIo cnt ByteString
encrypt partner d = do
	version <- gets tlssVersion
	set <- getCipherSet partner
	case (version, set) of
		(Just MS.TLS12, (TLS_RSA_WITH_AES_128_CBC_SHA, Just key)) -> do
			iv <- randomByteString 16
			let	e = encryptCBC (initAES key) iv d
			return $ iv `BS.append` e
		(_, (TLS_NULL_WITH_NULL_NULL, _)) -> return d
		_ -> throwError "clientWriteDecrypt: No keys or Bad cipher suite"

getCipherSet :: Partner -> TlsIo cnt (CipherSuite, Maybe ByteString)
getCipherSet partner = do
	cs <- gets $ case partner of
		Client -> tlssClientWriteCipherSuite
		Server -> tlssServerWriteCipherSuite
	mkey <- gets $ case partner of
		Client -> tlssClientWriteKey
		Server -> tlssServerWriteKey
	return (cs, mkey)

takeBodyMac :: Partner -> ByteString -> TlsIo cnt (ByteString, ByteString)
takeBodyMac partner bmp = do
	cs <- gets $ case partner of
		Client -> tlssClientWriteCipherSuite
		Server -> tlssServerWriteCipherSuite
	case cs of
		TLS_RSA_WITH_AES_128_CBC_SHA -> return $ bodyMac bmp
		TLS_NULL_WITH_NULL_NULL -> return (bmp, "")
		_ -> throwError "takeBodyMac: Bad cipher suite"

bodyMac :: ByteString -> (ByteString, ByteString)
bodyMac bs = let
	(bm, _) = BS.splitAt (BS.length bs - fromIntegral (BS.last bs) - 1) bs in
	BS.splitAt (BS.length bm - 20) bm

clientWriteMacKey :: TlsIo cnt (Maybe ByteString)
clientWriteMacKey = gets tlssClientWriteMacKey

updateHash :: ByteString -> TlsIo cnt ()
updateHash bs = do
	sha256 <- gets tlssSha256Ctx
	messages <- gets tlssHandshakeMessages
	tlss <- get
	put tlss {
		tlssSha256Ctx = SHA256.update sha256 bs,
		tlssHandshakeMessages = messages `BS.append` bs
	 }

finishedHash :: Partner -> TlsIo cnt ByteString
finishedHash partner = do
	mms <- gets tlssMasterSecret
	sha256 <- SHA256.finalize <$> gets tlssSha256Ctx
	version <- do
		mv <- gets tlssVersion
		case mv of
			Just v -> return v
			_ -> throwError "finishedHash: no version"
	case (version, mms) of
		(MS.TLS12, Just ms) -> return $
			MS.generateFinished version (partner == Client) ms sha256
		_ -> throwError "No master secrets"

handshakeMessages :: TlsIo cnt ByteString
handshakeMessages = gets tlssHandshakeMessages

getSequenceNumber :: Partner -> TlsIo cnt Word64
getSequenceNumber partner = gets $ case partner of
		Client -> tlssClientSequenceNumber
		Server -> tlssServerSequenceNumber

updateSequenceNumber :: Partner -> TlsIo cnt Word64
updateSequenceNumber partner = do
	sn <- gets $ case partner of
		Client -> tlssClientSequenceNumber
		Server -> tlssServerSequenceNumber
	tlss <- get
	put $ case partner of
		Client -> tlss { tlssClientSequenceNumber = succ sn }
		Server -> tlss { tlssServerSequenceNumber = succ sn }
	return sn

updateSequenceNumberSmart :: Partner -> TlsIo cnt ()
updateSequenceNumberSmart partner = do
	cs <- gets $ case partner of
		Client -> tlssClientWriteCipherSuite
		Server -> tlssServerWriteCipherSuite
	case cs of
		TLS_RSA_WITH_AES_128_CBC_SHA ->
			void $ updateSequenceNumber partner
		TLS_NULL_WITH_NULL_NULL -> return ()
		_ -> throwError "not implemented"

calcMac :: Partner -> ContentType -> Version -> ByteString -> TlsIo cnt ByteString
calcMac partner ct v body = do
	cs <- gets $ case partner of
		Client -> tlssClientWriteCipherSuite
		Server -> tlssServerWriteCipherSuite
	calcMacCs cs partner ct v body

calcMacCs :: CipherSuite -> Partner -> ContentType -> Version -> ByteString ->
	TlsIo cnt ByteString
calcMacCs TLS_RSA_WITH_AES_128_CBC_SHA partner ct v body = do
	sn <- getSequenceNumber partner
	let hashInput = BS.concat [
		word64ToByteString sn ,
		contentTypeToByteString ct,
		versionToByteString v,
		lenBodyToByteString 2 body ]
	Just macKey <- case partner of
		Client -> gets tlssClientWriteMacKey
		Server -> gets tlssServerWriteMacKey
	mv <- gets tlssVersion
	case mv of
		Just MS.TLS10 -> return $ MS.hmac SHA1.hash 64 macKey hashInput
		Just MS.TLS12 -> return $ MS.hmac SHA1.hash 64 macKey hashInput
		_ -> throwError "calcMacCs: not supported version"
calcMacCs TLS_NULL_WITH_NULL_NULL _ _ _ _ = return ""
calcMacCs _ _ _ _ _ = throwError "calcMac: not supported"

readVersion :: Partner -> TlsIo cnt Version
readVersion partner = byteStringToVersion <$> read partner 2

writeVersion :: Partner -> Version -> TlsIo cnt ()
writeVersion partner v = write partner $ versionToByteString v

readContentType :: Partner -> TlsIo cnt ContentType
readContentType partner = byteStringToContentType <$> read partner 1

writeContentType :: Partner -> ContentType -> TlsIo cnt ()
writeContentType partner ct = write partner $ contentTypeToByteString ct

getCipherSuite :: Partner -> TlsIo cnt CipherSuite
getCipherSuite partner = gets $ case partner of
	Client -> tlssClientWriteCipherSuite
	Server -> tlssServerWriteCipherSuite

showRandom :: Random -> String
showRandom (Random r) = showKey r

randomByteString :: Int -> TlsIo cnt ByteString
randomByteString len = do
	gen <- gets tlssRandomGen
	let (r, gen') = cprgGenerate len gen
	tlss <- get
	put tlss { tlssRandomGen = gen' }
	return r
