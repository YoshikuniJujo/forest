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

	TlsClient, runOpen, tPut, tGet, tGetLine, tGetByte, tGetContent,
) where

import Prelude hiding (read)

import Control.Applicative
import Control.Concurrent.STM
import "monads-tf" Control.Monad.Error
import "monads-tf" Control.Monad.State
import Data.Maybe
import Data.Word
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import System.IO
import "crypto-random" Crypto.Random
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.PubKey.HashDescr as RSA
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA

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

data TlsClient = TlsClient {
	tlsVersion :: CT.MSVersion,
	tlsCipherSuite :: CipherSuite,
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

runOpen :: TlsIo cnt () -> RSA.PrivateKey -> Handle -> IO TlsClient
runOpen opn pk cl = do
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
	(ret, st') <- runErrorT io `runStateT` st
	case ret of
		Right r -> return (r, st')
		Left err -> error err

tPut :: TlsClient -> BS.ByteString -> IO ()
tPut ts msg = case (vr, cs) of
	(CT.TLS12, TLS_RSA_WITH_AES_128_CBC_SHA) -> do
		ebody <- atomically $ do
			gen <- readTVar tvgen
			sn <- readTVar tvsn
			let (e, gen') = enc gen sn
			writeTVar tvgen gen'
			writeTVar tvsn $ succ sn
			return e
		BS.hPut h $ BS.concat [
			contentTypeToByteString ct,
			versionToByteString v,
			lenBodyToByteString 2 ebody ]
	_ -> error "tPut: not implemented"
	where
	vr = tlsVersion ts
	cs = tlsCipherSuite ts
	h = tlsHandle ts
	key = tlsServerWriteKey ts
	mk = tlsServerWriteMacKey ts
	ct = ContentTypeApplicationData
	v = Version 3 3
	tvsn = tlsServerSequenceNumber ts
	tvgen = tlsRandomGen ts
	enc gen sn = CT.encryptMessage gen key sn mk ct v msg

tGetWhole :: TlsClient -> IO BS.ByteString
tGetWhole ts = case (vr, cs) of
	(CT.TLS12, TLS_RSA_WITH_AES_128_CBC_SHA) -> do
		ct <- byteStringToContentType <$> BS.hGet h 1
		v <- byteStringToVersion <$> BS.hGet h 2
		enc <- BS.hGet h . byteStringToInt =<< BS.hGet h 2
		sn <- atomically $ do
			n <- readTVar tvsn
			writeTVar tvsn $ succ n
			return n
		case dec sn ct v enc of
			Right r -> return r
			Left err -> error err
	_ -> error "tGetWhole: not implemented"
	where
	vr = tlsVersion ts
	cs = tlsCipherSuite ts
	h = tlsHandle ts
	key = tlsClientWriteKey ts
	mk = tlsClientWriteMacKey ts
	tvsn = tlsClientSequenceNumber ts
	dec sn = CT.decryptMessage key sn mk

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
