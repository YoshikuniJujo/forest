{-# LANGUAGE PackageImports, OverloadedStrings, TupleSections,
	RankNTypes #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module TlsIo (
	TlsIo, TlsState(..), liftIO, throwError, catchError,
	randomByteString,
	Partner(..), runTlsIo, initTlsState,

	setClientRandom, setServerRandom,
	setVersion,
	getClientRandom, getServerRandom, getCipherSuite,
	cacheCipherSuite, flushCipherSuite,

	decryptRSA, generateKeys, updateHash, finishedHash, clientVerifyHash,
	clientVerifyHashEc,

	tlsEncryptMessage, tlsDecryptMessage,
	updateSequenceNumber,

	buffered, getContentType,
	Alert(..), AlertLevel(..), AlertDescription(..), alertVersion, processAlert,
	alertToByteString,
	CT.MSVersion(..),
--	CT.lenBodyToByteString,
	CT.decryptMessage, CT.hashSha1, CT.hashSha256,
	CT.encryptMessage,

	isEphemeralDH,
	getRandomGen,
	putRandomGen,
	getHandle,

	write,
	read,
--	CT.contentTypeToByteString,
--	CT.versionToByteString,
--	CT.intToByteString,
--	CT.byteStringToContentType,
--	CT.byteStringToVersion,
--	CT.byteStringToInt,

	CT.ContentType(..),
	CipherSuite(..), KeyExchange(..), BulkEncryption(..),
--	CT.Version(..),
) where

import Prelude hiding (read)

import Control.Applicative
import "monads-tf" Control.Monad.Error
import "monads-tf" Control.Monad.Error.Class
import "monads-tf" Control.Monad.State
import Data.String
import Data.Maybe
import Data.Word
import qualified Data.ByteString as BS
import "crypto-random" Crypto.Random
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.PubKey.HashDescr as RSA
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA

import qualified CryptoTools as CT
import CipherSuite

import Data.HandleLike

runTlsIo :: HandleLike h =>
	TlsIo h gen a -> TlsState h gen -> HandleMonad h (a, TlsState h gen)
runTlsIo io st = do
	(ret, st') <- runErrorT (io `catchError` processAlert)
		`runStateT` st
	case ret of
		Right r -> return (r, st')
		Left err -> error $ show err

processAlert :: HandleLike h => Alert -> TlsIo h gen a
processAlert alt = do
	write $ alertToByteString alt
	throwError alt

type TlsIo h gen = ErrorT Alert (StateT (TlsState h gen) (HandleMonad h))

data Alert
	= Alert AlertLevel AlertDescription String
	| NotDetected String
	deriving Show

alertToByteString :: Alert -> BS.ByteString
alertToByteString (Alert al ad _) = "\21\3\3\0\2" `BS.append`
	BS.pack [alertLevelToWord8 al, alertDescriptionToWord8 ad]
alertToByteString alt = error $ "alertToByteString: " ++ show alt

data AlertLevel
	= AlertLevelWarning
	| AlertLevelFatal
	| AlertLevelRaw Word8
	deriving Show

alertLevelToWord8 :: AlertLevel -> Word8
alertLevelToWord8 AlertLevelWarning = 1
alertLevelToWord8 AlertLevelFatal = 2
alertLevelToWord8 (AlertLevelRaw al) = al

data AlertDescription
	= AlertDescriptionCloseNotify
	| AlertDescriptionUnexpectedMessage
	| AlertDescriptionBadRecordMac
	| AlertDescriptionUnsupportedCertificate
	| AlertDescriptionCertificateExpired
	| AlertDescriptionCertificateUnknown
	| AlertDescriptionIllegalParameter
	| AlertDescriptionUnknownCa
	| AlertDescriptionDecodeError
	| AlertDescriptionDecryptError
	| AlertDescriptionProtocolVersion
	| AlertDescriptionRaw Word8
	deriving Show

alertDescriptionToWord8 :: AlertDescription -> Word8
alertDescriptionToWord8 AlertDescriptionCloseNotify = 0
alertDescriptionToWord8 AlertDescriptionUnexpectedMessage = 10
alertDescriptionToWord8 AlertDescriptionBadRecordMac = 20
alertDescriptionToWord8 AlertDescriptionUnsupportedCertificate = 43
alertDescriptionToWord8 AlertDescriptionCertificateExpired = 45
alertDescriptionToWord8 AlertDescriptionCertificateUnknown = 46
alertDescriptionToWord8 AlertDescriptionIllegalParameter = 47
alertDescriptionToWord8 AlertDescriptionUnknownCa = 48
alertDescriptionToWord8 AlertDescriptionDecodeError = 50
alertDescriptionToWord8 AlertDescriptionDecryptError = 51
alertDescriptionToWord8 AlertDescriptionProtocolVersion = 70
alertDescriptionToWord8 (AlertDescriptionRaw ad) = ad

alertVersion :: Alert
alertVersion = Alert AlertLevelFatal AlertDescriptionProtocolVersion
	"readByteString: bad Version"

instance Error Alert where
	strMsg = NotDetected

instance IsString Alert where
	fromString = NotDetected

data TlsState h gen = TlsState {
	tlssClientHandle :: h,
	tlssByteStringBuffer :: (Maybe CT.ContentType, BS.ByteString),

	tlssVersion :: Maybe CT.MSVersion,
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

	tlssRandomGen :: gen,
	tlssSha256Ctx :: SHA256.Ctx,
	tlssClientSequenceNumber :: Word64,
	tlssServerSequenceNumber :: Word64
 }

getClientRandom :: HandleLike h => TlsIo h gen (Maybe BS.ByteString)
getClientRandom = gets tlssClientRandom

getServerRandom :: HandleLike h => TlsIo h gen (Maybe BS.ByteString)
getServerRandom = gets tlssServerRandom

getCipherSuite :: HandleLike h => TlsIo h gen (Maybe CipherSuite)
getCipherSuite = gets tlssCachedCipherSuite

isEphemeralDH :: HandleLike h => TlsIo h gen Bool
isEphemeralDH = do
	me <- ((\cs -> let CipherSuite e _ = cs in e) <$>) `liftM`
		gets tlssCachedCipherSuite
--	liftIO . putStrLn $ "TlsIo.isEphemeralDH: " ++ show me
	case me of
		Just DHE_RSA -> return True
		Just ECDHE_RSA -> return True
		Just ECDHE_ECDSA -> return True
		Just RSA -> return False
		_ -> throwError "TlsIo.isEphemeralDH: Unknown algorithm"

initTlsState :: (HandleLike h, CPRG gen) => gen -> h -> TlsState h gen
initTlsState gen cl = TlsState {
	tlssClientHandle = cl,
	tlssByteStringBuffer = (Nothing, ""),

	tlssVersion = Nothing,
	tlssClientWriteCipherSuite = CipherSuite KE_NULL BE_NULL,
	tlssServerWriteCipherSuite = CipherSuite KE_NULL BE_NULL,
	tlssCachedCipherSuite = Nothing,

	tlssClientRandom = Nothing,
	tlssServerRandom = Nothing,
	tlssMasterSecret = Nothing,
	tlssClientWriteMacKey = Nothing,
	tlssServerWriteMacKey = Nothing,
	tlssClientWriteKey = Nothing,
	tlssServerWriteKey = Nothing,

	tlssRandomGen = gen,
	tlssSha256Ctx = SHA256.init,
	tlssClientSequenceNumber = 0,
	tlssServerSequenceNumber = 0
 }

getContentType :: HandleLike h => ((Word8, Word8) -> Bool)
	-> TlsIo h gen (CT.ContentType, (Word8, Word8), BS.ByteString)
	-> TlsIo h gen CT.ContentType
getContentType vc rd = do
	mct <- fst `liftM` gets tlssByteStringBuffer
	(\gt -> maybe gt return mct) $ do
		(ct, v, bf) <- rd
		unless (vc v) $ throwError alertVersion
		tlss <- get
		put tlss{ tlssByteStringBuffer = (Just ct, bf) }
		return ct

buffered :: HandleLike h =>
	Int -> TlsIo h gen (CT.ContentType, BS.ByteString) ->
	TlsIo h gen (CT.ContentType, BS.ByteString)
buffered n rd = do
	tlss@TlsState{ tlssByteStringBuffer = (mct, bf) } <- get
	if BS.length bf >= n
	then do	let (ret, bf') = BS.splitAt n bf
		put $ if BS.null bf'
			then tlss{ tlssByteStringBuffer = (Nothing, "") }
			else tlss{ tlssByteStringBuffer = (mct, bf') }
		return (fromJust mct, ret)
	else do	(ct', bf') <- rd
		unless (maybe True (== ct') mct) $
			throwError "Content Type confliction"
		when (BS.null bf') $ throwError "buffered: No data available"
		put tlss{ tlssByteStringBuffer = (Just ct', bf') }
		((ct' ,) . (bf `BS.append`) . snd) `liftM` buffered (n - BS.length bf) rd

randomByteString :: (HandleLike h, CPRG gen) => Int -> TlsIo h gen BS.ByteString
randomByteString len = do
	tlss@TlsState{ tlssRandomGen = gen } <- get
	let (r, gen') = cprgGenerate len gen
	put tlss { tlssRandomGen = gen' }
	return r

data Partner = Server | Client deriving (Show, Eq)

read :: HandleLike h => Int -> TlsIo h gen BS.ByteString
read n = do
	r <- lift . lift . flip hlGet n =<< gets tlssClientHandle
	if BS.length r == n
		then return r
		else throwError . strMsg $ "Basic.read: bad reading: " ++
			show (BS.length r) ++ " " ++ show n

write :: HandleLike h => BS.ByteString -> HandleLike h => TlsIo h gen ()
write dat = (lift . lift . flip hlPut dat) =<< gets tlssClientHandle

setVersion :: HandleLike h => (Word8, Word8) -> TlsIo h gen ()
setVersion v = do
	tlss <- get
	case CT.tupleToVersion v of
		Just v' -> put tlss { tlssVersion = Just v' }
		_ -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionProtocolVersion
			"setVersion: Not implemented"

			{-

setVersion :: HandleLike h => CT.Version -> TlsIo h gen ()
setVersion v = do
	tlss <- get
	case CT.versionToVersion v of
		Just v' -> put tlss { tlssVersion = Just v' }
		_ -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionProtocolVersion
			"setVersion: Not implemented"
			-}

setClientRandom, setServerRandom :: HandleLike h => BS.ByteString -> TlsIo h gen ()
setClientRandom cr = do
	tlss <- get
	put $ tlss { tlssClientRandom = Just cr }
setServerRandom sr = do
	tlss <- get
	put $ tlss { tlssServerRandom = Just sr }

cacheCipherSuite :: HandleLike h => CipherSuite -> TlsIo h gen ()
cacheCipherSuite cs = do
	tlss <- get
	put $ tlss { tlssCachedCipherSuite = Just cs }

flushCipherSuite :: HandleLike h => Partner -> TlsIo h gen ()
flushCipherSuite p = do
	tlss <- get
	case tlssCachedCipherSuite tlss of
		Just cs -> case p of
			Client -> put tlss { tlssClientWriteCipherSuite = cs }
			Server -> put tlss { tlssServerWriteCipherSuite = cs }
		_ -> throwError "No cached cipher suites"

decryptRSA :: (HandleLike h, CPRG gen) =>
	RSA.PrivateKey -> BS.ByteString -> TlsIo h gen BS.ByteString
decryptRSA pk e = do
	tlss@TlsState{ tlssRandomGen = gen } <- get
	let (ret, gen') = RSA.decryptSafer gen pk e
	put tlss{ tlssRandomGen = gen' }
	case ret of
		Right d -> return d
		Left err -> throwError . strMsg $ show err

generateKeys :: HandleLike h => BS.ByteString -> TlsIo h gen ()
generateKeys pms = do
--	h <- getHandle
	tlss@TlsState{
		tlssVersion = mv,
		tlssCachedCipherSuite = cs,
		tlssClientRandom = mcr,
		tlssServerRandom = msr } <- get
	mkl <- case cs of
		Just (CipherSuite _ AES_128_CBC_SHA) -> return 20
		Just (CipherSuite _ AES_128_CBC_SHA256) -> return 32
		_ -> throwError "generateKeys: not implemented"
--	lift . lift . hlDebug h . BSC.pack $ "CLIENT RANDOM: " ++ show mcr ++ "\n"
--	lift . lift . hlDebug h . BSC.pack $ "SERVER RANDOM: " ++ show msr ++ "\n"
	case (mv, CT.ClientRandom <$> mcr, CT.ServerRandom <$> msr) of
		(Just v, Just cr, Just sr) -> do
			let	ms = CT.generateMasterSecret v pms cr sr
				ems = CT.generateKeyBlock v cr sr ms $
					mkl * 2 + 32
				[cwmk, swmk, cwk, swk] = divide [mkl, mkl, 16, 16] ems
--			lift . lift . hlDebug h . BSC.pack $ "KEYS: " ++ show [cwmk, swmk, cwk, swk] ++ "\n"
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

updateHash :: HandleLike h => BS.ByteString -> TlsIo h gen ()
updateHash bs = do
	tlss@TlsState{ tlssSha256Ctx = sha256 } <- get
--	liftIO . putStrLn $ "PRE : " ++ show (SHA256.finalize sha256)
--	liftIO . putStrLn $ show bs
--	liftIO . putStrLn $ "POST: " ++ show (SHA256.finalize $ SHA256.update sha256 bs)
	put tlss { tlssSha256Ctx = SHA256.update sha256 bs }

finishedHash :: HandleLike h => Partner -> TlsIo h gen BS.ByteString
finishedHash partner = do
	mms <- gets tlssMasterSecret
	sha256 <- SHA256.finalize `liftM` gets tlssSha256Ctx
	mv <- gets tlssVersion
	case (mv, mms) of
		(Just CT.TLS12, Just ms) -> return $
			CT.generateFinished CT.TLS12 (partner == Client) ms sha256
		_ -> throwError "No master secrets"

clientVerifyHashEc :: HandleLike h => TlsIo h gen BS.ByteString
clientVerifyHashEc = gets $ SHA256.finalize . tlssSha256Ctx

clientVerifyHash :: HandleLike h => RSA.PublicKey -> TlsIo h gen BS.ByteString
clientVerifyHash pub = do
	sha256 <- gets $ SHA256.finalize . tlssSha256Ctx
	let Right hashed = RSA.padSignature (RSA.public_size pub) $
		RSA.digestToASN1 RSA.hashDescrSHA256 sha256
	return hashed

tlsEncryptMessage :: (HandleLike h, CPRG gen) =>
	CT.ContentType -> (Word8, Word8) -> BS.ByteString -> TlsIo h gen BS.ByteString
tlsEncryptMessage ct v msg = do
	version <- gets tlssVersion
	cs <- cipherSuite Server
	mwk <- writeKey Server
	sn <- sequenceNumber Server
	updateSequenceNumber Server
	mmk <- macKey Server
	gen <- gets tlssRandomGen
	mhs <- case cs of
		CipherSuite _ AES_128_CBC_SHA -> return $ Just CT.hashSha1
		CipherSuite _ AES_128_CBC_SHA256 -> return $ Just CT.hashSha256
		CipherSuite KE_NULL BE_NULL -> return Nothing
		_ -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionIllegalParameter
			"TlsIo.tlsEncryptMessage: not implemented cipher suite"
	case (version, mhs, mwk, mmk) of
		(Just CT.TLS12, Just hs, Just wk, Just mk)
			-> do	let (ret, gen') =
					CT.encryptMessage hs gen wk sn mk ct v msg
				tlss <- get
				put tlss{ tlssRandomGen = gen' }
				return ret
		(_, Nothing, _, _) -> return msg
		(_, _, Nothing, _) -> throwError "encryptMessage: No key"
		(_, _, _, Nothing) -> throwError "encryptMessage: No MAC key"
		(Just vsn, _, _, _) -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionProtocolVersion
			("TlsIo.EncryptMessage: not support the version: " ++ show vsn)
		(_, _, _, _) -> throwError "no version"

tlsDecryptMessage :: HandleLike h =>
	CT.ContentType -> (Word8, Word8) -> BS.ByteString -> TlsIo h gen BS.ByteString
tlsDecryptMessage ct v enc = do
	version <- gets tlssVersion
	cs <- cipherSuite Client
	mwk <- writeKey Client
	sn <- sequenceNumber Client
	mmk <- macKey Client
	case (version, cs, mwk, mmk) of
		(Just CT.TLS12, CipherSuite _ AES_128_CBC_SHA, Just key, Just mk)
			-> do	let emsg = CT.decryptMessage CT.hashSha1 key sn mk ct v enc
				case emsg of
					Right msg -> return msg
					Left err -> throwError $ Alert
						AlertLevelFatal
						AlertDescriptionBadRecordMac
						err
		(Just CT.TLS12, CipherSuite _ AES_128_CBC_SHA256, Just key, Just mk)
			-> do	let emsg = CT.decryptMessage CT.hashSha256 key sn mk ct v enc
				case emsg of
					Right msg -> return msg
					Left err -> throwError $ Alert
						AlertLevelFatal
						AlertDescriptionBadRecordMac
						err
		(_, CipherSuite KE_NULL BE_NULL, _, _) -> return enc
		_ -> throwError "TlsIo.tlsDecryptMessage: No keys or bad cipher suite"

sequenceNumber :: HandleLike h => Partner -> TlsIo h gen Word64
sequenceNumber partner = gets $ case partner of
		Client -> tlssClientSequenceNumber
		Server -> tlssServerSequenceNumber

updateSequenceNumber :: HandleLike h => Partner -> TlsIo h gen ()
updateSequenceNumber partner = do
	cs <- gets $ case partner of
		Client -> tlssClientWriteCipherSuite
		Server -> tlssServerWriteCipherSuite
	sn <- gets $ case partner of
		Client -> tlssClientSequenceNumber
		Server -> tlssServerSequenceNumber
	tlss <- get
	case cs of
		CipherSuite _ AES_128_CBC_SHA -> put $ case partner of
			Client -> tlss { tlssClientSequenceNumber = succ sn }
			Server -> tlss { tlssServerSequenceNumber = succ sn }
		CipherSuite _ AES_128_CBC_SHA256 -> put $ case partner of
			Client -> tlss { tlssClientSequenceNumber = succ sn }
			Server -> tlss { tlssServerSequenceNumber = succ sn }
		CipherSuite KE_NULL BE_NULL -> return ()
		_ -> throwError . strMsg $ "TlsIo.updateSequenceNumber: not implemented: " ++ show cs

cipherSuite :: HandleLike h => Partner -> TlsIo h gen CipherSuite
cipherSuite partner = gets $ case partner of
	Client -> tlssClientWriteCipherSuite
	Server -> tlssServerWriteCipherSuite

writeKey :: HandleLike h => Partner -> TlsIo h gen (Maybe BS.ByteString)
writeKey partner = gets $ case partner of
	Client -> tlssClientWriteKey
	Server -> tlssServerWriteKey

macKey :: HandleLike h => Partner -> TlsIo h gen (Maybe BS.ByteString)
macKey partner = gets $ case partner of
	Client -> tlssClientWriteMacKey
	Server -> tlssServerWriteMacKey

getRandomGen :: HandleLike h => TlsIo h gen gen
getRandomGen = gets tlssRandomGen

putRandomGen :: HandleLike h => gen -> TlsIo h gen ()
putRandomGen gen = do
	tlss <- get
	put tlss { tlssRandomGen = gen }

getHandle :: HandleLike h => TlsIo h gen h
getHandle = gets tlssClientHandle
