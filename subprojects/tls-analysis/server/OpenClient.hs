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

	TlsClient, runOpen, buffered, getContentType,
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
	ep <- createEntropyPool
	(ns, tlss) <- opn `runTlsIo` initTlsState ep cl
	let	gen = tlssRandomGen tlss
		csn = tlssClientSequenceNumber tlss
		ssn = tlssServerSequenceNumber tlss
		bfr = ""
	stt <- atomically $ newTVar TlsClientState {
		tlsBuffer = bfr,
		tlsRandomGen = gen,
		tlsClientSequenceNumber = csn,
		tlsServerSequenceNumber = ssn }
	return TlsClient {
		tlsConst = TlsClientConst {
			tlsNames = ns,
			tlsVersion = fromJust $ tlssVersion tlss,
			tlsCipherSuite = tlssClientWriteCipherSuite tlss,
			tlsHandle = tlssClientHandle tlss,
			tlsClientWriteMacKey = fromJust $ tlssClientWriteMacKey tlss,
			tlsServerWriteMacKey = fromJust $ tlssServerWriteMacKey tlss,
			tlsClientWriteKey = fromJust $ tlssClientWriteKey tlss,
			tlsServerWriteKey = fromJust $ tlssServerWriteKey tlss
		 },
		tlsState = stt
	 }

checkName :: TlsClient -> String -> Bool
checkName tc n = n `elem` tlsNames (tlsConst tc)

getName :: TlsClient -> Maybe String
getName tc = listToMaybe . tlsNames $ tlsConst tc

tPut :: TlsClient -> BS.ByteString -> IO ()
tPut ts = tPutWithCT ts ContentTypeApplicationData

tPutWithCT :: TlsClient -> ContentType -> BS.ByteString -> IO ()
tPutWithCT ts ct msg = do
	hs <- case cs of
		CipherSuite _ AES_128_CBC_SHA -> return hashSha1
		CipherSuite _ AES_128_CBC_SHA256 -> return hashSha256
		_ -> error "OpenClient.tPutWithCT"
	ebody <- atomically $ do
		gen <- tlsRandomGen <$> readTVar (tlsState ts)
		sn <- tlsServerSequenceNumber <$> readTVar (tlsState ts)
		let (e, gen') = enc hs gen sn
		modifyTVar (tlsState ts) $ setRandomGen gen'
		modifyTVar (tlsState ts) $ setServerSequenceNumber $ succ sn
		return e
	BS.hPut h $ BS.concat [
		contentTypeToByteString ct,
		versionToByteString v,
		lenBodyToByteString 2 ebody ]
	where
	(_vr, cs, h) = vrcsh ts
	key = tlsServerWriteKey $ tlsConst ts
	mk = tlsServerWriteMacKey $ tlsConst ts
	v = Version 3 3
--	tvsn = tlsServerSequenceNumber $ tlsState ts
--	tvgen = tlsRandomGen $ tlsState ts
	enc hs gen sn = encryptMessage hs gen key sn mk ct v msg

vrcsh :: TlsClient -> (MSVersion, CipherSuite, Handle)
vrcsh tc = (tlsVersion $ tlsConst tc,
	tlsCipherSuite $ tlsConst tc, tlsHandle $ tlsConst tc)

tGetWhole :: TlsClient -> IO BS.ByteString
tGetWhole ts = do
	ret <- tGetWholeWithCT ts
	case ret of
		(ContentTypeApplicationData, ad) -> return ad
		(ContentTypeAlert, "\SOH\NUL") -> do
			tPutWithCT ts ContentTypeAlert "\SOH\NUL"
			ioError $ mkIOError
				eofErrorType "tGetWhole" (Just h) Nothing
		_ -> do	tPutWithCT ts ContentTypeAlert "\2\10"
			error "not application data"
	where
	h = tlsHandle $ tlsConst ts

tGetWholeWithCT :: TlsClient -> IO (ContentType, BS.ByteString)
tGetWholeWithCT ts = do
	hs <- case cs of
		CipherSuite _ AES_128_CBC_SHA -> return hashSha1
		CipherSuite _ AES_128_CBC_SHA256 -> return hashSha256
		_ -> error "OpenClient.tGetWholeWithCT"
	ct <- byteStringToContentType <$> BS.hGet h 1
	v <- byteStringToVersion <$> BS.hGet h 2
	enc <- BS.hGet h . byteStringToInt =<< BS.hGet h 2
	sn <- atomically $ do
		n <- tlsClientSequenceNumber <$> readTVar (tlsState ts)
		modifyTVar (tlsState ts) $ setClientSequenceNumber $ succ n
		return n
	ret <- case dec hs sn ct v enc of
		Right r -> return r
		Left err -> error err
	return (ct, ret)
	where
	(_vr, cs, h) = vrcsh ts
	key = tlsClientWriteKey $ tlsConst ts
	mk = tlsClientWriteMacKey $ tlsConst ts
--	tvsn = tlsClientSequenceNumber $ tlsState ts
	dec hs sn = decryptMessage hs key sn mk

tGet :: TlsClient -> Int -> IO BS.ByteString
tGet tc n = do
	bfr <- tlsBuffer <$> (atomically . readTVar $ tlsState tc)
	if n <= BS.length bfr then atomically $ do
		let (ret, bfr') = BS.splitAt n bfr
		modifyTVar (tlsState tc) $ setBuffer bfr'
		return ret
	else do	msg <- tGetWhole tc
		atomically $ modifyTVar (tlsState tc) $ setBuffer msg
		(bfr `BS.append`) <$> tGet tc (n - BS.length bfr)

tGetLine :: TlsClient -> IO BS.ByteString
tGetLine tc = do
	bfr <- tlsBuffer <$> atomically (readTVar $ tlsState tc)
	case splitOneLine bfr of
		Just (l, ls) -> atomically $ do
			modifyTVar (tlsState tc) $ setBuffer ls
			return l
		_ -> do	msg <- tGetWhole tc
			atomically $ modifyTVar (tlsState tc) $ setBuffer msg
			(bfr `BS.append`) <$> tGetLine tc

tGetContent :: TlsClient -> IO BS.ByteString
tGetContent ts = do
	bfr <- tlsBuffer <$> atomically (readTVar $ tlsState ts)
	if BS.null bfr then tGetWhole ts else atomically $ do
		modifyTVar (tlsState ts) $ setBuffer BS.empty
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
	tPutWithCT tc ContentTypeAlert "\SOH\NUL"
	cn <- tGetWholeWithCT tc
	case cn of
		(ContentTypeAlert, "\SOH\NUL") -> return ()
		_ -> putStrLn "tClose: bad response"
	hClose h
	where
	h = tlsHandle $ tlsConst tc
