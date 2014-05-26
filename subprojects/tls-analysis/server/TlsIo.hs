{-# LANGUAGE PackageImports, OverloadedStrings, TupleSections #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module TlsIo (
	CT.Fragment(..), CT.Version, CT.ContentType(..),
	TlsIo, liftIO, throwError, catchError,
	readCached, randomByteString,
	Partner(..),

	readContentType, writeContentType, readVersion, writeVersion,
	readLen, writeLen,

	setVersion, setClientRandom, setServerRandom,
	cacheCipherSuite, flushCipherSuite,

	decryptRSA, generateKeys, updateHash, finishedHash, clientVerifyHash,

	encryptMessage, decryptMessage,
	updateSequenceNumber,

	TlsClient, runOpen, buffered, getContentType,
	Alert(..), AlertLevel(..), AlertDescription(..), alertVersion, processAlert,
) where

import Prelude hiding (read)

import Control.Applicative
import Control.Concurrent.STM
import "monads-tf" Control.Monad.Error
import "monads-tf" Control.Monad.Error.Class
import "monads-tf" Control.Monad.State
import Data.String
import Data.Maybe
import Data.Word
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import System.IO
import System.IO.Error
import "crypto-random" Crypto.Random
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.PubKey.HashDescr as RSA
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA

import qualified CryptoTools as CT

import Data.HandleLike

type TlsIo cnt = ErrorT Alert (StateT (TlsState cnt) IO)

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
	strMsg err = NotDetected err

instance IsString Alert where
	fromString err = NotDetected err

data TlsState cnt = TlsState {
	tlssClientHandle :: Handle,
	tlssByteStringBuffer :: (Maybe CT.ContentType, BS.ByteString),
	tlssContentCache :: [cnt],

	tlssVersion :: Maybe CT.MSVersion,
	tlssPrivateKey :: RSA.PrivateKey,
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

initTlsState :: EntropyPool -> Handle -> RSA.PrivateKey -> TlsState cnt
initTlsState ep cl pk = TlsState {
	tlssClientHandle = cl,
	tlssByteStringBuffer = (Nothing, ""),
	tlssContentCache = [],

	tlssVersion = Nothing,
	tlssPrivateKey = pk,
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
	-> TlsIo cnt (CT.ContentType, CT.Version, BS.ByteString)
	-> TlsIo cnt CT.ContentType
getContentType vc rd = do
	mct <- fst <$> gets tlssByteStringBuffer
	(\gt -> maybe gt return mct) $ do
		(ct, v, bf) <- rd
		unless (vc v) $ throwError alertVersion
		tlss <- get
		put tlss{ tlssByteStringBuffer = (Just ct, bf) }
		return ct

buffered :: Int -> TlsIo cnt (CT.ContentType, BS.ByteString) ->
	TlsIo cnt (CT.ContentType, BS.ByteString)
buffered n rd = do
	tlss@TlsState{ tlssByteStringBuffer = (mct, bf) } <- get
	if BS.length bf >= n
	then do -- liftIO $ putStrLn "FROM BUFFER"
		let (ret, bf') = BS.splitAt n bf
		put $ if BS.null bf'
			then tlss{ tlssByteStringBuffer = (Nothing, "") }
			else tlss{ tlssByteStringBuffer = (mct, bf') }
		return (fromJust mct, ret)
	else do -- liftIO $ putStrLn "FROM IO"
		(ct', bf') <- rd
		unless (maybe True (== ct') mct) $
			throwError "Content Type confliction"
		when (BS.null bf') $ throwError "buffered: No data available"
		put tlss{ tlssByteStringBuffer = (Just ct', bf') }
		(ct' ,) . (bf `BS.append`) . snd <$> buffered (n - BS.length bf) rd

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

readContentType :: TlsIo cnt CT.ContentType
readContentType = CT.byteStringToContentType <$> read 1

writeContentType :: CT.ContentType -> TlsIo cnt ()
writeContentType = write . CT.contentTypeToByteString

readVersion :: TlsIo cnt CT.Version
readVersion = CT.byteStringToVersion <$> read 2

writeVersion :: CT.Version -> TlsIo cnt ()
writeVersion = write . CT.versionToByteString

readLen :: Int -> TlsIo cnt BS.ByteString
readLen n = read . CT.byteStringToInt =<< read n

writeLen :: Int -> BS.ByteString -> TlsIo cnt ()
writeLen n bs = write (CT.intToByteString n $ BS.length bs) >> write bs

read :: Int -> TlsIo cnt BS.ByteString
read n = do
	r <- liftIO . flip BS.hGet n =<< gets tlssClientHandle
	if BS.length r == n
		then return r
		else throwError $ strMsg $ "Basic.read: bad reading: " ++
			show (BS.length r) ++ " " ++ show n

write :: BS.ByteString -> TlsIo cnt ()
write dat = liftIO . flip BS.hPut dat =<< gets tlssClientHandle

setVersion :: CT.Version -> TlsIo cnt ()
setVersion v = do
	tlss <- get
	case CT.versionToVersion v of
		Just v' -> put tlss { tlssVersion = Just v' }
		_ -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionProtocolVersion
			"setVersion: Not implemented"

setClientRandom, setServerRandom :: CT.Random -> TlsIo cnt ()
setClientRandom (CT.Random cr) = do
	tlss <- get
	put $ tlss { tlssClientRandom = Just cr }
setServerRandom (CT.Random sr) = do
	tlss <- get
	put $ tlss { tlssServerRandom = Just sr }

cacheCipherSuite :: CT.CipherSuite -> TlsIo cnt ()
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
	tlss@TlsState{ tlssRandomGen = gen } <- get
	let (ret, gen') = RSA.decryptSafer gen pk e
	put tlss{ tlssRandomGen = gen' }
	case ret of
		Right d -> return d
		Left err -> throwError $ strMsg $ show err

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

encryptMessage :: CT.ContentType -> CT.Version -> BS.ByteString -> TlsIo cnt BS.ByteString
encryptMessage ct v msg = do
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

decryptMessage :: CT.ContentType -> CT.Version -> BS.ByteString -> TlsIo cnt BS.ByteString
decryptMessage ct v enc = do
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
		CT.TLS_RSA_WITH_AES_128_CBC_SHA -> put $ case partner of
			Client -> tlss { tlssClientSequenceNumber = succ sn }
			Server -> tlss { tlssServerSequenceNumber = succ sn }
		CT.TLS_NULL_WITH_NULL_NULL -> return ()
		_ -> throwError "not implemented"

cipherSuite :: Partner -> TlsIo cnt CT.CipherSuite
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

data TlsClient = TlsClient {
	tlsVersion :: CT.MSVersion,
	tlsCipherSuite :: CT.CipherSuite,
	tlsHandle :: Handle,
	tlsBuffer :: TVar BS.ByteString,
	tlsRandomGen :: TVar SystemRNG,
	tlsClientWriteMacKey :: BS.ByteString,
	tlsServerWriteMacKey :: BS.ByteString,
	tlsClientWriteKey :: BS.ByteString,
	tlsServerWriteKey :: BS.ByteString,
	tlsClientSequenceNumber :: TVar Word64,
	tlsServerSequenceNumber :: TVar Word64
 }

instance HandleLike TlsClient where
	hlPut = tPut
	hlGet = tGet
	hlGetLine = tGetLine
	hlGetContent = tGetContent
	hlClose = tClose

runOpen :: Handle -> RSA.PrivateKey -> TlsIo cnt () -> IO TlsClient
runOpen cl pk opn = do
	ep <- createEntropyPool
	(_, tlss) <- opn `runTlsIo` initTlsState ep cl pk
	tvgen <- atomically . newTVar $ tlssRandomGen tlss
	tvcsn <- atomically . newTVar $ tlssClientSequenceNumber tlss
	tvssn <- atomically . newTVar $ tlssServerSequenceNumber tlss
	tvbfr <- atomically $ newTVar ""
	return TlsClient {
		tlsVersion = fromJust $ tlssVersion tlss,
		tlsCipherSuite = tlssClientWriteCipherSuite tlss,
		tlsHandle = tlssClientHandle tlss,
		tlsBuffer = tvbfr,
		tlsRandomGen = tvgen,
		tlsClientWriteMacKey = fromJust $ tlssClientWriteMacKey tlss,
		tlsServerWriteMacKey = fromJust $ tlssServerWriteMacKey tlss,
		tlsClientWriteKey = fromJust $ tlssClientWriteKey tlss,
		tlsServerWriteKey = fromJust $ tlssServerWriteKey tlss,
		tlsClientSequenceNumber = tvcsn,
		tlsServerSequenceNumber = tvssn
	 }

runTlsIo :: TlsIo cnt a -> TlsState cnt -> IO (a, TlsState cnt)
runTlsIo io st = do
	(ret, st') <- runErrorT (io `catchError` processAlert)
		`runStateT` st
	case ret of
		Right r -> return (r, st')
		Left err -> error $ show err

processAlert :: Alert -> TlsIo cnt a
processAlert alt = do
	write $ alertToByteString alt
	throwError alt

tPut :: TlsClient -> BS.ByteString -> IO ()
tPut ts = tPutWithCT ts CT.ContentTypeApplicationData

tPutWithCT :: TlsClient -> CT.ContentType -> BS.ByteString -> IO ()
tPutWithCT ts ct msg = case (vr, cs) of
	(CT.TLS12, CT.TLS_RSA_WITH_AES_128_CBC_SHA) -> do
		ebody <- atomically $ do
			gen <- readTVar tvgen
			sn <- readTVar tvsn
			let (e, gen') = enc gen sn
			writeTVar tvgen gen'
			writeTVar tvsn $ succ sn
			return e
		BS.hPut h $ BS.concat [
			CT.contentTypeToByteString ct,
			CT.versionToByteString v,
			CT.lenBodyToByteString 2 ebody ]
	_ -> error "tPut: not implemented"
	where
	(vr, cs, h) = vrcsh ts
	key = tlsServerWriteKey ts
	mk = tlsServerWriteMacKey ts
--	ct = ContentTypeApplicationData
	v = CT.Version 3 3
	tvsn = tlsServerSequenceNumber ts
	tvgen = tlsRandomGen ts
	enc gen sn = CT.encryptMessage gen key sn mk ct v msg

vrcsh :: TlsClient -> (CT.MSVersion, CT.CipherSuite, Handle)
vrcsh tc = (tlsVersion tc, tlsCipherSuite tc, tlsHandle tc)

tGetWhole :: TlsClient -> IO BS.ByteString
tGetWhole ts = do
	ret <- tGetWholeWithCT ts
	case ret of
		(CT.ContentTypeApplicationData, ad) -> return ad
		(CT.ContentTypeAlert, "\SOH\NUL") -> do
			tPutWithCT ts CT.ContentTypeAlert "\SOH\NUL"
			ioError $ mkIOError
				eofErrorType "tGetWhole" (Just h) Nothing
		_ -> do	tPutWithCT ts CT.ContentTypeAlert "\2\10"
			error "not application data"
	where
	h = tlsHandle ts

tGetWholeWithCT :: TlsClient -> IO (CT.ContentType, BS.ByteString)
tGetWholeWithCT ts = case (vr, cs) of
	(CT.TLS12, CT.TLS_RSA_WITH_AES_128_CBC_SHA) -> do
		ct <- CT.byteStringToContentType <$> BS.hGet h 1
--		liftIO $ print ct
		v <- CT.byteStringToVersion <$> BS.hGet h 2
		enc <- BS.hGet h . CT.byteStringToInt =<< BS.hGet h 2
		sn <- atomically $ do
			n <- readTVar tvsn
			writeTVar tvsn $ succ n
			return n
		ret <- case dec sn ct v enc of
			Right r -> return r
			Left err -> error err
			{-
		case (ct, ret) of
			(ContentTypeApplicationData, _) -> return ret
			(ContentTypeAlert, "\SOH\NUL") -> do
				tPutWithCT ts ContentTypeAlert "\SOH\NUL"
				ioError $ mkIOError
					eofErrorType "tGetWhole" (Just h) Nothing
			_ -> error "not implemented yet"
			-}
		return (ct, ret)
	_ -> error "tGetWhole: not implemented"
	where
	(vr, cs, h) = vrcsh ts
	key = tlsClientWriteKey ts
	mk = tlsClientWriteMacKey ts
	tvsn = tlsClientSequenceNumber ts
	dec sn = CT.decryptMessage key sn mk

{-
tGetByte :: TlsClient -> IO Word8
tGetByte ts = do
	bfr <- atomically . readTVar $ tlsBuffer ts
	if BS.null bfr then do
		msg <- tGetWhole ts
		atomically $ case BS.uncons msg of
			Just (b, bs) -> do
				writeTVar (tlsBuffer ts) bs
				return b
			_ -> error "tGetByte: empty data"
	else atomically $ case BS.uncons bfr of
		Just (b, bs) -> do
			writeTVar (tlsBuffer ts) bs
			return b
		_ -> error "tGetByte: never occur"
		-}

tGet :: TlsClient -> Int -> IO BS.ByteString
tGet tc n = do
	bfr <- atomically . readTVar $ tlsBuffer tc
	if n <= BS.length bfr then atomically $ do
		let (ret, bfr') = BS.splitAt n bfr
		writeTVar (tlsBuffer tc) bfr'
		return ret
	else do	msg <- tGetWhole tc
		atomically $ writeTVar (tlsBuffer tc) msg
		(bfr `BS.append`) <$> tGet tc (n - BS.length bfr)

tGetLine :: TlsClient -> IO BS.ByteString
tGetLine tc = do
	bfr <- atomically . readTVar $ tlsBuffer tc
	case splitOneLine bfr of
		Just (l, ls) -> atomically $ do
			writeTVar (tlsBuffer tc) ls
			return l
		_ -> do	msg <- tGetWhole tc
			atomically $ writeTVar (tlsBuffer tc) msg
			(bfr `BS.append`) <$> tGetLine tc

tGetContent :: TlsClient -> IO BS.ByteString
tGetContent ts = do
	bfr <- atomically . readTVar $ tlsBuffer ts
	if BS.null bfr then tGetWhole ts else atomically $ do
		writeTVar (tlsBuffer ts) BS.empty
		return bfr

splitOneLine :: BS.ByteString -> Maybe (BS.ByteString, BS.ByteString)
splitOneLine bs = case ('\r' `BSC.elem` bs, '\n' `BSC.elem` bs) of
	(True, _) -> let
		(l, ls) = BSC.span (/= '\r') bs
		Just ('\r', ls') = BSC.uncons ls in
		case BSC.uncons ls' of
			Just ('\n', ls'') -> Just (l, ls'')
			_ -> Just (l, ls')
	(_, True) -> let
		(l, ls) = BSC.span (/= '\n') bs
		Just ('\n', ls') = BSC.uncons ls in Just (l, ls')
	_ -> Nothing

tClose :: TlsClient -> IO ()
tClose tc = do
	tPutWithCT tc CT.ContentTypeAlert "\SOH\NUL"
	tGetWholeWithCT tc >>= print
	hClose h
	where
	h = tlsHandle tc
