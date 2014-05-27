{-# LANGUAGE PackageImports, OverloadedStrings, TupleSections #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module TlsIo (
	TlsIo, TlsState(..), liftIO, throwError, catchError,
	randomByteString,
	Partner(..), runTlsIo, initTlsState,

	readContentType, writeContentType, readVersion, writeVersion,
	readLen, writeLen,

	setVersion, setClientRandom, setServerRandom,
	cacheCipherSuite, flushCipherSuite,

	decryptRSA, generateKeys, updateHash, finishedHash, clientVerifyHash,

	tlsEncryptMessage, tlsDecryptMessage,
	updateSequenceNumber,

	buffered, getContentType,
	Alert(..), AlertLevel(..), AlertDescription(..), alertVersion, processAlert,
	alertToByteString,
	CT.MSVersion(..),
	CT.lenBodyToByteString,
	CT.byteStringToInt,
	CT.decryptMessage,
	CT.encryptMessage,
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
import System.IO
import "crypto-random" Crypto.Random
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.PubKey.HashDescr as RSA
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA

import qualified CryptoTools as CT

runTlsIo :: TlsIo a -> TlsState -> IO (a, TlsState)
runTlsIo io st = do
	(ret, st') <- runErrorT (io `catchError` processAlert)
		`runStateT` st
	case ret of
		Right r -> return (r, st')
		Left err -> error $ show err

processAlert :: Alert -> TlsIo a
processAlert alt = do
	write $ alertToByteString alt
	throwError alt

type TlsIo = ErrorT Alert (StateT TlsState IO)

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

data TlsState = TlsState {
	tlssClientHandle :: Handle,
	tlssByteStringBuffer :: (Maybe CT.ContentType, BS.ByteString),

	tlssVersion :: Maybe CT.MSVersion,
	tlssClientWriteCipherSuite :: CT.CipherSuite,
	tlssServerWriteCipherSuite :: CT.CipherSuite,
	tlssCachedCipherSuite :: Maybe CT.CipherSuite,

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

initTlsState :: EntropyPool -> Handle -> TlsState
initTlsState ep cl = TlsState {
	tlssClientHandle = cl,
	tlssByteStringBuffer = (Nothing, ""),

	tlssVersion = Nothing,
	tlssClientWriteCipherSuite = CT.TLS_NULL_WITH_NULL_NULL,
	tlssServerWriteCipherSuite = CT.TLS_NULL_WITH_NULL_NULL,
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

getContentType :: (CT.Version -> Bool)
	-> TlsIo (CT.ContentType, CT.Version, BS.ByteString)
	-> TlsIo CT.ContentType
getContentType vc rd = do
	mct <- fst <$> gets tlssByteStringBuffer
	(\gt -> maybe gt return mct) $ do
		(ct, v, bf) <- rd
		unless (vc v) $ throwError alertVersion
		tlss <- get
		put tlss{ tlssByteStringBuffer = (Just ct, bf) }
		return ct

buffered :: Int -> TlsIo (CT.ContentType, BS.ByteString) ->
	TlsIo (CT.ContentType, BS.ByteString)
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
		(ct' ,) . (bf `BS.append`) . snd <$> buffered (n - BS.length bf) rd

randomByteString :: Int -> TlsIo BS.ByteString
randomByteString len = do
	tlss@TlsState{ tlssRandomGen = gen } <- get
	let (r, gen') = cprgGenerate len gen
	put tlss { tlssRandomGen = gen' }
	return r

data Partner = Server | Client deriving (Show, Eq)

readContentType :: TlsIo CT.ContentType
readContentType = CT.byteStringToContentType <$> read 1

writeContentType :: CT.ContentType -> TlsIo ()
writeContentType = write . CT.contentTypeToByteString

readVersion :: TlsIo CT.Version
readVersion = CT.byteStringToVersion <$> read 2

writeVersion :: CT.Version -> TlsIo ()
writeVersion = write . CT.versionToByteString

readLen :: Int -> TlsIo BS.ByteString
readLen n = read . CT.byteStringToInt =<< read n

writeLen :: Int -> BS.ByteString -> TlsIo ()
writeLen n bs = write (CT.intToByteString n $ BS.length bs) >> write bs

read :: Int -> TlsIo BS.ByteString
read n = do
	r <- liftIO . flip BS.hGet n =<< gets tlssClientHandle
	if BS.length r == n
		then return r
		else throwError . strMsg $ "Basic.read: bad reading: " ++
			show (BS.length r) ++ " " ++ show n

write :: BS.ByteString -> TlsIo ()
write dat = liftIO . flip BS.hPut dat =<< gets tlssClientHandle

setVersion :: CT.Version -> TlsIo ()
setVersion v = do
	tlss <- get
	case CT.versionToVersion v of
		Just v' -> put tlss { tlssVersion = Just v' }
		_ -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionProtocolVersion
			"setVersion: Not implemented"

setClientRandom, setServerRandom :: CT.Random -> TlsIo ()
setClientRandom (CT.Random cr) = do
	tlss <- get
	put $ tlss { tlssClientRandom = Just cr }
setServerRandom (CT.Random sr) = do
	tlss <- get
	put $ tlss { tlssServerRandom = Just sr }

cacheCipherSuite :: CT.CipherSuite -> TlsIo ()
cacheCipherSuite cs = do
	tlss <- get
	put $ tlss { tlssCachedCipherSuite = Just cs }

flushCipherSuite :: Partner -> TlsIo ()
flushCipherSuite p = do
	tlss <- get
	case tlssCachedCipherSuite tlss of
		Just cs -> case p of
			Client -> put tlss { tlssClientWriteCipherSuite = cs }
			Server -> put tlss { tlssServerWriteCipherSuite = cs }
		_ -> throwError "No cached cipher suites"

decryptRSA :: RSA.PrivateKey -> BS.ByteString -> TlsIo BS.ByteString
decryptRSA pk e = do
	tlss@TlsState{ tlssRandomGen = gen } <- get
	let (ret, gen') = RSA.decryptSafer gen pk e
	put tlss{ tlssRandomGen = gen' }
	case ret of
		Right d -> return d
		Left err -> throwError . strMsg $ show err

generateKeys :: BS.ByteString -> TlsIo ()
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

updateHash :: BS.ByteString -> TlsIo ()
updateHash bs = do
	tlss@TlsState{ tlssSha256Ctx = sha256 } <- get
	put tlss { tlssSha256Ctx = SHA256.update sha256 bs }

finishedHash :: Partner -> TlsIo BS.ByteString
finishedHash partner = do
	mms <- gets tlssMasterSecret
	sha256 <- SHA256.finalize <$> gets tlssSha256Ctx
	mv <- gets tlssVersion
	case (mv, mms) of
		(Just CT.TLS12, Just ms) -> return $
			CT.generateFinished CT.TLS12 (partner == Client) ms sha256
		_ -> throwError "No master secrets"

clientVerifyHash :: RSA.PublicKey -> TlsIo BS.ByteString
clientVerifyHash pub = do
	sha256 <- gets $ SHA256.finalize . tlssSha256Ctx
	let Right hashed = RSA.padSignature (RSA.public_size pub) $
		RSA.digestToASN1 RSA.hashDescrSHA256 sha256
	return hashed

tlsEncryptMessage :: CT.ContentType -> CT.Version -> BS.ByteString -> TlsIo BS.ByteString
tlsEncryptMessage ct v msg = do
	version <- gets tlssVersion
	cs <- cipherSuite Server
	mwk <- writeKey Server
	sn <- sequenceNumber Server
	updateSequenceNumber Server
	mmk <- macKey Server
	gen <- gets tlssRandomGen
	case (version, cs, mwk, mmk) of
		(Just CT.TLS12, CT.TLS_RSA_WITH_AES_128_CBC_SHA, Just wk, Just mk)
			-> do	let (ret, gen') =
					CT.encryptMessage gen wk sn mk ct v msg
				tlss <- get
				put tlss{ tlssRandomGen = gen' }
				return ret
		(_, CT.TLS_NULL_WITH_NULL_NULL, _, _) -> return msg
		(_, _, Nothing, _) -> throwError "encryptMessage: No key"
		(_, _, _, Nothing) -> throwError "encryptMessage: No MAC key"
		(Just CT.TLS12, _, _, _) -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionIllegalParameter
			"encryptMessage: not implemented cipher suite"
		(Just vsn, _, _, _) -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionProtocolVersion
			("encryptMessage: not support the version: " ++ show vsn)
		(_, _, _, _) -> throwError "no version"

tlsDecryptMessage :: CT.ContentType -> CT.Version -> BS.ByteString -> TlsIo BS.ByteString
tlsDecryptMessage ct v enc = do
	version <- gets tlssVersion
	cs <- cipherSuite Client
	mwk <- writeKey Client
	sn <- sequenceNumber Client
	mmk <- macKey Client
	case (version, cs, mwk, mmk) of
		(Just CT.TLS12, CT.TLS_RSA_WITH_AES_128_CBC_SHA, Just key, Just mk)
			-> do	let emsg = CT.decryptMessage key sn mk ct v enc
				case emsg of
					Right msg -> return msg
					Left err -> throwError $ Alert
						AlertLevelFatal
						AlertDescriptionBadRecordMac
						err
		(_, CT.TLS_NULL_WITH_NULL_NULL, _, _) -> return enc
		_ -> throwError "decryptMessage: No keys or bad cipher suite"

sequenceNumber :: Partner -> TlsIo Word64
sequenceNumber partner = gets $ case partner of
		Client -> tlssClientSequenceNumber
		Server -> tlssServerSequenceNumber

updateSequenceNumber :: Partner -> TlsIo ()
updateSequenceNumber partner = do
	cs <- gets $ case partner of
		Client -> tlssClientWriteCipherSuite
		Server -> tlssServerWriteCipherSuite
	sn <- gets $ case partner of
		Client -> tlssClientSequenceNumber
		Server -> tlssServerSequenceNumber
	tlss <- get
	case cs of
		CT.TLS_RSA_WITH_AES_128_CBC_SHA -> put $ case partner of
			Client -> tlss { tlssClientSequenceNumber = succ sn }
			Server -> tlss { tlssServerSequenceNumber = succ sn }
		CT.TLS_NULL_WITH_NULL_NULL -> return ()
		_ -> throwError "not implemented"

cipherSuite :: Partner -> TlsIo CT.CipherSuite
cipherSuite partner = gets $ case partner of
	Client -> tlssClientWriteCipherSuite
	Server -> tlssServerWriteCipherSuite

writeKey :: Partner -> TlsIo (Maybe BS.ByteString)
writeKey partner = gets $ case partner of
	Client -> tlssClientWriteKey
	Server -> tlssServerWriteKey

macKey :: Partner -> TlsIo (Maybe BS.ByteString)
macKey partner = gets $ case partner of
	Client -> tlssClientWriteMacKey
	Server -> tlssServerWriteMacKey
