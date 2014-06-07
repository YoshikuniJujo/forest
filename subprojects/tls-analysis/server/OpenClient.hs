{-# LANGUAGE PackageImports, OverloadedStrings, TupleSections, TypeFamilies #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module OpenClient (
	Fragment(..), Version, ContentType(..),
	TlsIo, liftIO, throwError, catchError,
	randomByteString,
	Partner(..),

	readContentType, writeContentType, readVersion, writeVersion,
	readLen, writeLen,

	setVersion, setClientRandom, setServerRandom,
	getClientRandom, getServerRandom, getCipherSuite,
	cacheCipherSuite, flushCipherSuite,

	decryptRSA, generateKeys, updateHash, finishedHash, clientVerifyHash,
	clientVerifyHashEc,

	tlsEncryptMessage, tlsDecryptMessage,
	updateSequenceNumber,

	TlsClient,
	TlsClientConst,
	TlsClientState(..),
	runOpen,

	buffered, getContentType,
	Alert(..), AlertLevel(..), AlertDescription(..), alertVersion, processAlert,
	checkName, getName,

	isEphemeralDH,
) where

import Prelude hiding (read)

import Control.Applicative
import Control.Concurrent.STM
import "monads-tf" Control.Monad.Error
import Data.Maybe
import Data.Word
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import System.IO
import System.IO.Error
import "crypto-random" Crypto.Random

import Data.HandleLike

import TlsIo
import Types

import "monads-tf" Control.Monad.State

stateToStm :: StateT s IO a -> TVar s -> IO a
stateToStm m v = do
	s <- atomically $ readTVar v
	(r, s') <- m `runStateT` s
	atomically $ writeTVar v s'
	return r

toStm :: (TlsClientConst -> StateT TlsClientState IO a) -> TlsClient -> IO a
toStm s (TlsClient tc ts) = stateToStm (s tc) ts

toStm1 :: (TlsClientConst -> a -> StateT TlsClientState IO b) ->
	TlsClient -> a -> IO b
toStm1 s (TlsClient tc ts) x = stateToStm (s tc x) ts

data TlsClient = TlsClient {
	tlsConst :: TlsClientConst,
	tlsState :: TVar TlsClientState }

data TlsClientConst = TlsClientConst {
	tlsNames :: [String],
	tlsVersion :: MSVersion,
	tlsCipherSuite :: CipherSuite,
	tlsHandle :: Handle,
	tlsClientWriteMacKey :: BS.ByteString,
	tlsServerWriteMacKey :: BS.ByteString,
	tlsClientWriteKey :: BS.ByteString,
	tlsServerWriteKey :: BS.ByteString }

data TlsClientState = TlsClientState {
	tlsBuffer :: BS.ByteString,
	tlsRandomGen :: SystemRNG,
	tlsClientSequenceNumber :: Word64,
	tlsServerSequenceNumber :: Word64 }

setBuffer :: BS.ByteString -> TlsClientState -> TlsClientState
setBuffer bs st = st { tlsBuffer = bs }

setRandomGen :: SystemRNG -> TlsClientState -> TlsClientState
setRandomGen rg st = st { tlsRandomGen = rg }

setClientSequenceNumber, setServerSequenceNumber ::
	Word64 -> TlsClientState -> TlsClientState
setClientSequenceNumber sn st = st { tlsClientSequenceNumber = sn }
setServerSequenceNumber sn st = st { tlsServerSequenceNumber = sn }

instance HandleLike TlsClient where
	type HandleMonad TlsClient = IO
	hlPut = tPut
	hlGet = tGet
	hlGetLine = tGetLine
	hlGetContent = tGetContent
	hlClose = tClose

runOpen :: Handle -> TlsIo [String] -> IO TlsClient
runOpen cl opn = do
	tc <- runOpenSt cl opn
	ep <- createEntropyPool
	let	gen = cprgCreate ep
		csn = 1
		ssn = 1
		bfr = ""
	stt <- atomically $ newTVar TlsClientState {
		tlsBuffer = bfr,
		tlsRandomGen = gen,
		tlsClientSequenceNumber = csn,
		tlsServerSequenceNumber = ssn }
	return $ TlsClient { tlsConst = tc, tlsState = stt }

runOpenSt :: Handle -> TlsIo [String] -> IO TlsClientConst
runOpenSt cl opn = do
	ep <- createEntropyPool
	(ns, tlss) <- opn `runTlsIo` initTlsState ep cl
	return TlsClientConst {
		tlsNames = ns,
		tlsVersion = fromJust $ tlssVersion tlss,
		tlsCipherSuite = tlssClientWriteCipherSuite tlss,
		tlsHandle = tlssClientHandle tlss,
		tlsClientWriteMacKey = fromJust $ tlssClientWriteMacKey tlss,
		tlsServerWriteMacKey = fromJust $ tlssServerWriteMacKey tlss,
		tlsClientWriteKey = fromJust $ tlssClientWriteKey tlss,
		tlsServerWriteKey = fromJust $ tlssServerWriteKey tlss }

checkName :: TlsClient -> String -> Bool
checkName tc n = n `elem` tlsNames (tlsConst tc)

getName :: TlsClient -> Maybe String
getName tc = listToMaybe . tlsNames $ tlsConst tc

tPut :: TlsClient -> BS.ByteString -> IO ()
tPut = toStm1 tPutSt

tGet :: TlsClient -> Int -> IO BS.ByteString
tGet = toStm1 tGetSt

tGetLine :: TlsClient -> IO BS.ByteString
tGetLine = toStm tGetLineSt

tGetContent :: TlsClient -> IO BS.ByteString
tGetContent = toStm tGetContentSt

--

tPutSt :: TlsClientConst -> BS.ByteString -> StateT TlsClientState IO ()
tPutSt tc = tPutWithCtSt tc ContentTypeApplicationData

tPutWithCtSt :: TlsClientConst -> ContentType -> BS.ByteString ->
	StateT TlsClientState IO ()
tPutWithCtSt tc ct msg = do
	hs <- case cs of
		CipherSuite _ AES_128_CBC_SHA -> return hashSha1
		CipherSuite _ AES_128_CBC_SHA256 -> return hashSha256
		_ -> error "OpenClient.tPutWithCT"
	gen <- gets tlsRandomGen
	sn <- gets tlsServerSequenceNumber
	let (ebody, gen') = enc hs gen sn
	modify $ setRandomGen gen'
	modify . setServerSequenceNumber $ succ sn
	liftIO . BS.hPut h $ BS.concat [
		contentTypeToByteString ct,
		versionToByteString v,
		lenBodyToByteString 2 ebody ]
	where
	(_vr, cs, h) = vrcshSt tc
	key = tlsServerWriteKey tc
	mk = tlsServerWriteMacKey tc
	v = Version 3 3
	enc hs gen sn = encryptMessage hs gen key sn mk ct v msg

vrcshSt :: TlsClientConst -> (MSVersion, CipherSuite, Handle)
vrcshSt tc = (tlsVersion tc, tlsCipherSuite tc, tlsHandle tc)

tGetWholeSt :: TlsClientConst -> StateT TlsClientState IO BS.ByteString
tGetWholeSt tc = do
	ret <- tGetWholeWithCtSt tc
	case ret of
		(ContentTypeApplicationData, ad) -> return ad
		(ContentTypeAlert, "\SOH\NUL") -> do
			tPutWithCtSt tc ContentTypeAlert "\SOH\NUL"
			liftIO . ioError $ mkIOError
				eofErrorType "tGetWhole" (Just h) Nothing
		_ -> do	tPutWithCtSt tc ContentTypeAlert "\2\10"
			error "not application data"
	where
	h = tlsHandle tc

tGetWholeWithCtSt :: TlsClientConst ->
	StateT TlsClientState IO (ContentType, BS.ByteString)
tGetWholeWithCtSt tc = do
	hs <- case cs of
		CipherSuite _ AES_128_CBC_SHA -> return hashSha1
		CipherSuite _ AES_128_CBC_SHA256 -> return hashSha256
		_ -> error "OpenClient.tGetWholeWithCT"
	ct <- byteStringToContentType <$> liftIO (BS.hGet h 1)
	v <- byteStringToVersion <$> liftIO (BS.hGet h 2)
	enc <- liftIO . BS.hGet h . byteStringToInt =<< liftIO (BS.hGet h 2)
	sn <- gets tlsClientSequenceNumber
	modify $ setClientSequenceNumber $ succ sn
	ret <- case dec hs sn ct v enc of
		Right r -> return r
		Left err -> error err
	return (ct, ret)
	where
	(_vr, cs, h) = vrcshSt tc
	key = tlsClientWriteKey tc
	mk = tlsClientWriteMacKey tc
	dec hs sn = decryptMessage hs key sn mk

tGetSt :: TlsClientConst -> Int -> StateT TlsClientState IO BS.ByteString
tGetSt tc n = do
	bfr <- gets tlsBuffer
	if n <= BS.length bfr then do
		let (ret, bfr') = BS.splitAt n bfr
		modify $ setBuffer bfr'
		return ret
	else do	msg <- tGetWholeSt tc
		modify $ setBuffer msg
		(bfr `BS.append`) <$> tGetSt tc (n - BS.length bfr)

tGetLineSt :: TlsClientConst -> StateT TlsClientState IO BS.ByteString
tGetLineSt tc = do
	bfr <- gets tlsBuffer
	case splitOneLine bfr of
		Just (l, ls) -> do
			modify $ setBuffer ls
			return l
		_ -> do	msg <- tGetWholeSt tc
			modify $ setBuffer msg
			(bfr `BS.append`) <$> tGetLineSt tc

tGetContentSt :: TlsClientConst -> StateT TlsClientState IO BS.ByteString
tGetContentSt tc = do
	bfr <- gets tlsBuffer
	if BS.null bfr then tGetWholeSt tc else do
		modify $ setBuffer BS.empty
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
tClose = toStm tCloseSt

tCloseSt :: TlsClientConst -> StateT TlsClientState IO ()
tCloseSt tc = do
	tPutWithCtSt tc ContentTypeAlert "\SOH\NUL"
	cn <- tGetWholeWithCtSt tc
	case cn of
		(ContentTypeAlert, "\SOH\NUL") -> return ()
		_ -> liftIO $ putStrLn "tClose: bad response"
	liftIO $ hClose h
	where
	h = tlsHandle tc
