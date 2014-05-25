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

	TlsServer, runOpen, tPut, tGetByte, tGetLine, tGet, tGetContent, tClose,

	debugPrintKeys, Option(..), isOptHelloVersion,
) where

import Prelude hiding (read)

import System.IO
import System.IO.Error
import Control.Concurrent.STM
import Control.Applicative
import "monads-tf" Control.Monad.Error
import "monads-tf" Control.Monad.State
import Data.Maybe
import Data.Word
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import "crypto-random" Crypto.Random
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.PubKey.HashDescr as RSA
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA

import qualified CryptoTools as CT
import Basic
import Data.HandleLike

data Option
	= OptPmsVerErr
	| OptHelloVersion Word8 Word8
	deriving (Show, Eq)

isOptHelloVersion :: Option -> Bool
isOptHelloVersion (OptHelloVersion _ _) = True
isOptHelloVersion _ = False

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

instance HandleLike TlsServer where
	hlPut = tPut
	hlGet = tGet
	hlGetLine = tGetLine
	hlGetContent = tGetContent
	hlClose = tClose

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

runOpen :: TlsIo cnt () -> Handle -> IO TlsServer
runOpen opn sv = do
	ep <- createEntropyPool
	(_, tlss) <- opn `runTlsIo` initTlsClientState ep sv
	tvgen <- atomically . newTVar $ tlssRandomGen tlss
	tvcsn <- atomically . newTVar $ tlssClientSequenceNumber tlss
	tvssn <- atomically . newTVar $ tlssServerSequenceNumber tlss
	tvbfr <- atomically $ newTVar ""
	return TlsServer {
		tlsVersion = fromJust $ tlssVersion tlss,
		tlsCipherSuite = tlssClientWriteCipherSuite tlss,
		tlsHandle = tlssHandle tlss,
		tlsBuffer = tvbfr,
		tlsRandomGen = tvgen,
		tlsClientWriteMacKey = fromJust $ tlssClientWriteMacKey tlss,
		tlsServerWriteMacKey = fromJust $ tlssServerWriteMacKey tlss,
		tlsClientWriteKey = fromJust $ tlssClientWriteKey tlss,
		tlsServerWriteKey = fromJust $ tlssServerWriteKey tlss,
		tlsClientSequenceNumber = tvcsn,
		tlsServerSequenceNumber = tvssn
	 }

runTlsIo :: TlsIo cnt a -> TlsClientState cnt -> IO (a, TlsClientState cnt)
runTlsIo io st = do
	(ret, st') <- runErrorT io `runStateT` st
	case ret of
		Right r -> return (r, st')
		Left err -> error err

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
			"\texpected: " ++ show n ++ "byte\n" ++
			"\tactural : " ++ show (BS.length r) ++ "byte\n"

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
--	liftIO $ putStrLn $ "Pre Master Secret: " ++ show pms
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
--	liftIO $ print mwk
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

data TlsServer = TlsServer {
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

tPut :: TlsServer -> BS.ByteString -> IO ()
tPut ts = tPutWithCT ts ContentTypeApplicationData

tPutWithCT :: TlsServer -> ContentType -> BS.ByteString -> IO ()
tPutWithCT ts ct msg = case (vr, cs) of
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
			lenBodyToByteString 2 ebody]
		
	_ -> error "tPut: not implemented"
	where
	vr = tlsVersion ts
	cs = tlsCipherSuite ts
	h = tlsHandle ts
	key = tlsClientWriteKey ts
	mk = tlsClientWriteMacKey ts
	v = Version 3 3
	tvsn = tlsClientSequenceNumber ts
	tvgen = tlsRandomGen ts
	enc gen sn = CT.encryptMessage gen key sn mk ct v msg

tGetWhole :: TlsServer -> IO BS.ByteString
tGetWhole ts = do
	ret <- tGetWholeWithCT ts
	case ret of
		(ContentTypeApplicationData, ad) -> return ad
		(ContentTypeAlert, "\SOH\NUL") -> do
			tPutWithCT ts ContentTypeAlert "\SOH\NUL"
			ioError $ mkIOError
				eofErrorType "tGetWhole" (Just h) Nothing
		_ -> error "not impolemented yet"
	where
	h = tlsHandle ts

tGetWholeWithCT :: TlsServer -> IO (ContentType, BS.ByteString)
tGetWholeWithCT ts = case (vr, cs) of
	(CT.TLS12, TLS_RSA_WITH_AES_128_CBC_SHA) -> do
		ct <- byteStringToContentType <$> BS.hGet h 1
		v <- byteStringToVersion <$> BS.hGet h 2
		enc <- BS.hGet h . byteStringToInt =<< BS.hGet h 2
		sn <- atomically $ do
			n <- readTVar tvsn
			writeTVar tvsn $ succ n
			return n
		case dec sn ct v enc of
			Right r -> return (ct, r)
			Left err -> error err
	_ -> error "tPut: not implemented"
	where
	vr = tlsVersion ts
	cs = tlsCipherSuite ts
	h = tlsHandle ts
	key = tlsServerWriteKey ts
	mk = tlsServerWriteMacKey ts
	tvsn = tlsServerSequenceNumber ts
	dec sn = CT.decryptMessage key sn mk

tGetByte :: TlsServer -> IO Word8
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

tGet :: TlsServer -> Int -> IO BS.ByteString
tGet ts n = do
	bfr <- atomically . readTVar $ tlsBuffer ts
	if n <= BS.length bfr then atomically $ do
		let (ret, bfr') = BS.splitAt n bfr
		writeTVar (tlsBuffer ts) bfr'
		return ret
	else do	msg <- tGetWhole ts
		atomically $ writeTVar (tlsBuffer ts) msg
		(bfr `BS.append`) <$> tGet ts (n - BS.length bfr)

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

tGetLine :: TlsServer -> IO BS.ByteString
tGetLine ts = do
	bfr <- atomically . readTVar $ tlsBuffer ts
	case splitOneLine bfr of
		Just (l, ls) -> atomically $ do
			writeTVar (tlsBuffer ts) ls
			return l
		_ -> do	msg <- tGetWhole ts
			atomically $ writeTVar (tlsBuffer ts) msg
			(bfr `BS.append`) <$> tGetLine ts

tGetContent :: TlsServer -> IO BS.ByteString
tGetContent ts = do
	bfr <- atomically . readTVar $ tlsBuffer ts
	if BS.null bfr then tGetWhole ts else atomically $ do
		writeTVar (tlsBuffer ts) BS.empty
		return bfr

debugPrintKeys :: TlsIo cnt ()
debugPrintKeys = do
	Just ms <- gets tlssMasterSecret
	Just cwmk <- gets tlssClientWriteMacKey
	Just swmk <- gets tlssServerWriteMacKey
	Just cwk <- gets tlssClientWriteKey
	Just swk <- gets tlssServerWriteKey
--	Just cwi <- gets tlssClientWriteIv
--	Just swi <- gets tlssServerWriteIv
	liftIO $ do
		putStrLn "### GENERATED KEYS ###"
		putStrLn $ "\tMaster Secret : " ++ show ms
		putStrLn $ "\tClntWr MAC Key: " ++ showKeySingle cwmk
		putStrLn $ "\tSrvrWr MAC Key: " ++ showKeySingle swmk
		putStrLn $ "\tClntWr Key    : " ++ showKeySingle cwk
		putStrLn $ "\tSrvrWr Key    : " ++ showKeySingle swk
--		putStrLn $ "\tClntWr IV     : " ++ showKeySingle cwi
--		putStrLn $ "\tSrvrWr IV     : " ++ showKeySingle swi

tClose :: TlsServer -> IO ()
tClose ts = do
	tPutWithCT ts ContentTypeAlert "\SOH\NUL"
	tGetWholeWithCT ts >>= print
	hClose h
	where
	h = tlsHandle ts
