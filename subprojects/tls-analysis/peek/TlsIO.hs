{-# LANGUAGE PackageImports, OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module TlsIO (
	TlsIO, runTlsIO, evalTlsIO, initTlsState, liftIO,
	Partner(..), opponent, ServerHandle(..), ClientHandle(..),
	read, write, readLen, writeLen,

	readCached,

	clientId, clientWriteMacKey,

	setClientRandom, setServerRandom, setVersion,
	cacheCipherSuite, flushCipherSuite,
	generateMasterSecret,

	decryptRSA, decrypt, encrypt, takeBodyMac,
	encryptRSA,

	masterSecret,

--	debugPrintKeys,
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
{-
import MasterSecret(
	CipherSuite(..), Random(..), ContentType(..),
	contentTypeToByteString, byteStringToVersion, Version(..),
	versionToByteString, byteStringToContentType, Version(..),
	showKey, showKeySingle, byteStringToInt, intToByteString)
	-}
import Basic
-- import Basic
-- import Tools

import qualified Crypto.Hash.MD5 as MD5
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA256 as SHA256

-- import MAC
-- import ToByteString

import "crypto-random" Crypto.Random

type TlsIO cnt = ErrorT String (StateT (TlsState cnt) IO)

data TlsState cnt = TlsState {
	tlssVersion :: Maybe MS.MSVersion,
	tlssClientId :: Int,
	tlssServerHandle :: Handle,
	tlssClientHandle :: Handle,
	tlssPrivateKey :: PrivateKey,
	tlssClientWriteCipherSuite :: CipherSuite,
	tlssServerWriteCipherSuite :: CipherSuite,
	tlssCachedCipherSuite :: Maybe CipherSuite,
	tlssClientRandom :: Maybe ByteString,
	tlssServerRandom :: Maybe ByteString,
	tlssMasterSecret :: Maybe ByteString,
	tlssExpandedMasterSecret :: Maybe ByteString,
	tlssClientWriteMacKey :: Maybe ByteString,
	tlssServerWriteMacKey :: Maybe ByteString,
	tlssClientWriteKey :: Maybe ByteString,
	tlssServerWriteKey :: Maybe ByteString,
	tlssClientWriteIv :: Maybe ByteString,
	tlssServerWriteIv :: Maybe ByteString,
	tlssMd5Ctx :: MD5.Ctx,
	tlssSha1Ctx :: SHA1.Ctx,
	tlssSha256Ctx :: SHA256.Ctx,
	tlssClientSequenceNumber :: Word64,
	tlssServerSequenceNumber :: Word64,
	tlssDecryptIv :: Maybe ByteString,
	tlssRandomGen :: SystemRNG,
	tlssHandshakeMessages :: ByteString,
	tlssContentCacheClient :: [cnt],
	tlssContentCacheServer :: [cnt]
 } deriving Show

instance Show SystemRNG where
	show _ = "System Random Generator"

readCached :: Partner -> TlsIO cnt [cnt] -> TlsIO cnt cnt
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

setVersion :: MS.Version -> TlsIO cnt ()
setVersion v = do
	tlss <- get
	case MS.versionToVersion v of
		Just v' -> put tlss { tlssVersion = Just v' }
		_ -> throwError "setVersion: Not implemented"

setIv :: Partner -> ByteString -> TlsIO cnt ()
setIv partner iv = do
	tlss <- get
	put $ case partner of
		Client -> tlss { tlssClientWriteIv = Just iv }
		Server -> tlss { tlssServerWriteIv = Just iv }

instance Show MD5.Ctx where
	show = show . MD5.finalize

instance Show SHA1.Ctx where
	show = show . SHA1.finalize

instance Show SHA256.Ctx where
	show = show . SHA256.finalize

data ServerHandle = ServerHandle Handle deriving Show
data ClientHandle = ClientHandle Handle deriving Show

initTlsState :: EntropyPool -> Int -> ClientHandle -> ServerHandle -> PrivateKey -> TlsState cnt
initTlsState ep cid (ClientHandle cl) (ServerHandle sv) pk = TlsState {
	tlssVersion = Nothing,
	tlssClientId = cid,
	tlssServerHandle = sv,
	tlssClientHandle = cl,
	tlssPrivateKey = pk,
	tlssClientWriteCipherSuite = TLS_NULL_WITH_NULL_NULL,
	tlssServerWriteCipherSuite = TLS_NULL_WITH_NULL_NULL,
	tlssCachedCipherSuite = Nothing,
	tlssClientRandom = Nothing,
	tlssServerRandom = Nothing,
	tlssMasterSecret = Nothing,
	tlssExpandedMasterSecret = Nothing,
	tlssClientWriteMacKey = Nothing,
	tlssServerWriteMacKey = Nothing,
	tlssClientWriteKey = Nothing,
	tlssServerWriteKey = Nothing,
	tlssClientWriteIv = Nothing,
	tlssServerWriteIv = Nothing,
	tlssMd5Ctx = MD5.init,
	tlssSha1Ctx = SHA1.init,
	tlssSha256Ctx = SHA256.init,
	tlssClientSequenceNumber = 0,
	tlssServerSequenceNumber = 0,
	tlssDecryptIv = Nothing,
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
handle Client = tlssClientHandle

runTlsIO :: TlsIO cnt a -> TlsState cnt -> IO (Either String a, TlsState cnt)
runTlsIO io ts = runErrorT io `runStateT` ts

evalTlsIO :: TlsIO cnt a -> EntropyPool -> Int -> ClientHandle -> ServerHandle -> PrivateKey -> IO a
evalTlsIO io ep cid cl sv pk = do
	ret <- runErrorT io `evalStateT` initTlsState ep cid cl sv pk
	case ret of
		Right r -> return r
		Left err -> error err

read :: Partner -> Int -> TlsIO cnt ByteString
read partner n = do
	h <- gets $ handle partner
	r <- liftIO $ BS.hGet h n
	if BS.length r == n
		then return r
		else throwError $ "Basic.read: bad reading: " ++
			show (BS.length r) ++ " " ++ show n

write :: Partner -> ByteString -> TlsIO cnt ()
write partner dat = do
	h <- gets $ handle partner
	liftIO $ BS.hPut h dat

readLen :: Partner -> Int -> TlsIO cnt ByteString
readLen partner n = do
	len <- read partner n
	read partner $ byteStringToInt len

writeLen :: Partner -> Int -> ByteString -> TlsIO cnt ()
writeLen partner n bs = do
	write partner . intToByteString n $ BS.length bs
	write partner bs

decryptRSA :: ByteString -> TlsIO cnt ByteString
decryptRSA e = do
	pk <- gets tlssPrivateKey
	case RSA.decrypt Nothing pk e of
		Right d -> return d
		Left err -> throwError $ show err

encryptRSA :: PublicKey -> ByteString -> TlsIO cnt ByteString
encryptRSA pub pln = do
	g <- gets tlssRandomGen
	tlss <- get
	let (Right e, g') = RSA.encrypt g pub pln
	put tlss { tlssRandomGen = g' }
	return e

setClientRandom, setServerRandom :: Random -> TlsIO cnt ()
setClientRandom (Random cr) = do
	tlss <- get
	put $ tlss { tlssClientRandom = Just cr }
setServerRandom (Random sr) = do
	tlss <- get
	put $ tlss { tlssServerRandom = Just sr }

cacheCipherSuite :: CipherSuite -> TlsIO cnt ()
cacheCipherSuite cs = do
	tlss <- get
	put $ tlss { tlssCachedCipherSuite = Just cs }

flushCipherSuite :: Partner -> TlsIO cnt ()
flushCipherSuite p = do
	tlss <- get
	case tlssCachedCipherSuite tlss of
		Just cs -> case p of
			Client -> put tlss { tlssClientWriteCipherSuite = cs }
			Server -> put tlss { tlssServerWriteCipherSuite = cs }
		_ -> throwError "No cached cipher suites"

generateMasterSecret :: ByteString -> TlsIO cnt ()
generateMasterSecret pms = do
	mv <- gets tlssVersion
	mcr <- gets $ (MS.ClientRandom <$>) . tlssClientRandom
	msr <- gets $ (MS.ServerRandom <$>) . tlssServerRandom
	case (mv, mcr, msr) of
		(Just v, Just cr, Just sr) -> do
			let	ms = MS.generateMasterSecret v pms cr sr
				ems = MS.generateKeyBlock v cr sr ms 104
				[cwmk, swmk, cwk, swk, cwi, swi] =
					divide [
						20, 20,
						16, 16,
						16, 16 ] ems
			tlss <- get
			put $ tlss {
				tlssMasterSecret = Just ms,
				tlssExpandedMasterSecret = Just ems,
				tlssClientWriteMacKey = Just cwmk,
				tlssServerWriteMacKey = Just swmk,
				tlssClientWriteKey = Just cwk,
				tlssServerWriteKey = Just swk,
				tlssClientWriteIv = Just cwi,
				tlssServerWriteIv = Just swi
			 }
		_ -> throwError "No client random / No server random"

masterSecret :: TlsIO cnt (Maybe ByteString)
masterSecret = gets tlssMasterSecret

divide :: [Int] -> BS.ByteString -> [BS.ByteString]
divide [] _ = []
divide (n : ns) bs
	| bs == BS.empty = []
	| otherwise = let (x, xs) = BS.splitAt n bs in x : divide ns xs

{-
debugPrintKeys :: TlsIO cnt ()
debugPrintKeys = do
	Just cwmk <- gets tlssClientWriteMacKey
	Just swmk <- gets tlssServerWriteMacKey
	Just cwk <- gets tlssClientWriteKey
	Just swk <- gets tlssServerWriteKey
	Just cwi <- gets tlssClientWriteIv
	Just swi <- gets tlssServerWriteIv
	liftIO $ do
		putStrLn "### GENERATED KEYS ###"
		putStrLn $ "\tClntWr MAC Key: " ++ showKeySingle cwmk
		putStrLn $ "\tSrvrWr MAC Key: " ++ showKeySingle swmk
		putStrLn $ "\tClntWr Key    : " ++ showKeySingle cwk
		putStrLn $ "\tSrvrWr Key    : " ++ showKeySingle swk
		putStrLn $ "\tClntWr IV     : " ++ showKeySingle cwi
		putStrLn $ "\tSrvrWr IV     : " ++ showKeySingle swi
		-}

debugShowKeys :: TlsIO cnt [String]
debugShowKeys = do
	Just cwmk <- gets tlssClientWriteMacKey
	Just swmk <- gets tlssServerWriteMacKey
	Just cwk <- gets tlssClientWriteKey
	Just swk <- gets tlssServerWriteKey
	Just cwi <- gets tlssClientWriteIv
	Just swi <- gets tlssServerWriteIv
	return [
		"### GENERATED KEYS ###",
		"ClntWr MAC Key: " ++ showKeySingle cwmk,
		"SrvrWr MAC Key: " ++ showKeySingle swmk,
		"ClntWr Key    : " ++ showKeySingle cwk,
		"SrvrWr Key    : " ++ showKeySingle swk,
		"ClntWr IV     : " ++ showKeySingle cwi,
		"SrvrWr IV     : " ++ showKeySingle swi ]

decrypt :: Partner -> ByteString -> TlsIO cnt ByteString
decrypt partner e = do
	version <- gets tlssVersion
	set <- getCipherSet partner
	case (version, set) of
		(Just MS.TLS10, (TLS_RSA_WITH_AES_128_CBC_SHA, Just key, Just iv)) ->
			return $ decryptCBC (initAES key) iv e
		(Just MS.TLS12, (TLS_RSA_WITH_AES_128_CBC_SHA, Just key, _)) -> do
--			liftIO $ print e
			tlss <- get
			put tlss { tlssDecryptIv = Just $ BS.take 16 e }
			let d = decryptCBC (initAES key)
				(BS.take 16 e) (BS.drop 16 e)
--			liftIO . putStrLn $ "cipher   : " ++ show e
--			liftIO . putStrLn $ "decrypted: " ++ show d
			return d
		(_, (TLS_NULL_WITH_NULL_NULL, _, _)) -> return e
		_ -> throwError "clientWriteDecrypt: No keys or Bad cipher suite"

encrypt :: Partner -> ByteString -> TlsIO cnt ByteString
encrypt partner d = do
	version <- gets tlssVersion
	set <- getCipherSet partner
	case (version, set) of
		(Just MS.TLS10, (TLS_RSA_WITH_AES_128_CBC_SHA, Just key, Just iv)) -> do
			let e = encryptCBC (initAES key) iv d
			setIv partner $ BS.drop (BS.length e - 16) e
			return e
		(Just MS.TLS12, (TLS_RSA_WITH_AES_128_CBC_SHA, Just key, _)) -> do
--			Just iv <- gets tlssDecryptIv
			iv <- randomByteString 16
			let	-- iv = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
				e = encryptCBC (initAES key) iv d
--			liftIO . putStrLn $ "palin    : " ++ show d
--			liftIO $ print iv
--			liftIO $ print e
			return $ iv `BS.append` e
		(_, (TLS_NULL_WITH_NULL_NULL, _, _)) -> return d
		_ -> throwError "clientWriteDecrypt: No keys or Bad cipher suite"

getCipherSet :: Partner -> TlsIO cnt (CipherSuite, Maybe ByteString, Maybe ByteString)
getCipherSet partner = do
	cs <- gets $ case partner of
		Client -> tlssClientWriteCipherSuite
		Server -> tlssServerWriteCipherSuite
	mkey <- gets $ case partner of
		Client -> tlssClientWriteKey
		Server -> tlssServerWriteKey
	miv <- gets $ case partner of
		Client -> tlssClientWriteIv
		Server -> tlssServerWriteIv
	return (cs, mkey, miv)

takeBodyMac :: Partner -> ByteString -> TlsIO cnt (ByteString, ByteString)
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

clientId :: TlsIO cnt Int
clientId = gets tlssClientId

clientWriteMacKey :: TlsIO cnt (Maybe ByteString)
clientWriteMacKey = gets tlssClientWriteMacKey

updateHash :: ByteString -> TlsIO cnt ()
updateHash bs = do
	md5 <- gets tlssMd5Ctx
	sha1 <- gets tlssSha1Ctx
	sha256 <- gets tlssSha256Ctx
	messages <- gets tlssHandshakeMessages
	tlss <- get
{-
	liftIO $ do
		putStrLn $ "MD5 : " ++ show (MD5.update md5 bs)
		putStrLn $ "SHA1: " ++ show (SHA1.update sha1 bs)
-}
	put tlss {
		tlssMd5Ctx = MD5.update md5 bs,
		tlssSha1Ctx = SHA1.update sha1 bs,
		tlssSha256Ctx = SHA256.update sha256 bs,
		tlssHandshakeMessages = messages `BS.append` bs
	 }

finishedHash :: Partner -> TlsIO cnt ByteString
finishedHash partner = do
	mms <- gets tlssMasterSecret
	md5 <- MD5.finalize <$> gets tlssMd5Ctx
	sha1 <- SHA1.finalize <$> gets tlssSha1Ctx
	sha256 <- SHA256.finalize <$> gets tlssSha256Ctx
	version <- do
		mv <- gets tlssVersion
		case mv of
			Just v -> return v
			_ -> throwError "finishedHash: no version"
	case (version, mms) of
		(MS.TLS10, Just ms) -> return .
			MS.generateFinished version (partner == Client) ms $
				md5 `BS.append` sha1
		(MS.TLS12, Just ms) -> return $
			MS.generateFinished version (partner == Client) ms sha256
		_ -> throwError "No master secrets"

handshakeMessages :: TlsIO cnt ByteString
handshakeMessages = gets tlssHandshakeMessages

getSequenceNumber :: Partner -> TlsIO cnt Word64
getSequenceNumber partner = gets $ case partner of
		Client -> tlssClientSequenceNumber
		Server -> tlssServerSequenceNumber

updateSequenceNumber :: Partner -> TlsIO cnt Word64
updateSequenceNumber partner = do
	sn <- gets $ case partner of
		Client -> tlssClientSequenceNumber
		Server -> tlssServerSequenceNumber
	tlss <- get
	put $ case partner of
		Client -> tlss { tlssClientSequenceNumber = succ sn }
		Server -> tlss { tlssServerSequenceNumber = succ sn }
	return sn

updateSequenceNumberSmart :: Partner -> TlsIO cnt ()
updateSequenceNumberSmart partner = do
	cs <- gets $ case partner of
		Client -> tlssClientWriteCipherSuite
		Server -> tlssServerWriteCipherSuite
	case cs of
		TLS_RSA_WITH_AES_128_CBC_SHA ->
			void $ updateSequenceNumber partner
		TLS_NULL_WITH_NULL_NULL -> return ()
		_ -> throwError "not implemented"

calcMac :: Partner -> ContentType -> Version -> ByteString -> TlsIO cnt ByteString
calcMac partner ct v body = do
	cs <- gets $ case partner of
		Client -> tlssClientWriteCipherSuite
		Server -> tlssServerWriteCipherSuite
	calcMacCs cs partner ct v body

calcMacCs :: CipherSuite -> Partner -> ContentType -> Version -> ByteString ->
	TlsIO cnt ByteString
calcMacCs TLS_RSA_WITH_AES_128_CBC_SHA partner ct v body = do
	sn <- getSequenceNumber partner
	let hashInput = BS.concat [
		word64ToByteString sn ,
		contentTypeToByteString ct,
		versionToByteString v,
		lenBodyToByteString 2 body ]
--	liftIO . putStrLn $ "hashInput = " ++ show hashInput
	Just macKey <- case partner of
		Client -> gets tlssClientWriteMacKey
		Server -> gets tlssServerWriteMacKey
	mv <- gets tlssVersion
	case mv of
		Just MS.TLS10 -> return $ MS.hmac SHA1.hash 64 macKey hashInput
--		Just MS.TLS12 -> return $ hmac SHA256.hash 64 macKey hashInput
		Just MS.TLS12 -> return $ MS.hmac SHA1.hash 64 macKey hashInput
		_ -> throwError "calcMacCs: not supported version"
calcMacCs TLS_NULL_WITH_NULL_NULL _ _ _ _ = return ""
calcMacCs _ _ _ _ _ = throwError "calcMac: not supported"

readVersion :: Partner -> TlsIO cnt Version
readVersion partner = byteStringToVersion <$> read partner 2

writeVersion :: Partner -> Version -> TlsIO cnt ()
writeVersion partner v = write partner $ versionToByteString v

readContentType :: Partner -> TlsIO cnt ContentType
readContentType partner = byteStringToContentType <$> read partner 1

writeContentType :: Partner -> ContentType -> TlsIO cnt ()
writeContentType partner ct = write partner $ contentTypeToByteString ct

getCipherSuite :: Partner -> TlsIO cnt CipherSuite
getCipherSuite partner = gets $ case partner of
	Client -> tlssClientWriteCipherSuite
	Server -> tlssServerWriteCipherSuite

showRandom :: Random -> String
showRandom (Random r) = showKey r

randomByteString :: Int -> TlsIO cnt ByteString
randomByteString len = do
	gen <- gets tlssRandomGen
	let (r, gen') = cprgGenerate len gen
	tlss <- get
	put tlss { tlssRandomGen = gen' }
	return r
