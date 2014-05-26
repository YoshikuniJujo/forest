{-# LANGUAGE PackageImports, OverloadedStrings, TupleSections #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module OpenClient (
	Fragment(..), Version, ContentType(..),
	TlsIo, liftIO, throwError, catchError,
	randomByteString,
	Partner(..),

	readContentType, writeContentType, readVersion, writeVersion,
	readLen, writeLen,

	setVersion, setClientRandom, setServerRandom,
	cacheCipherSuite, flushCipherSuite,

	decryptRSA, generateKeys, updateHash, finishedHash, clientVerifyHash,

	tlsEncryptMessage, tlsDecryptMessage,
	updateSequenceNumber,

	TlsClient, runOpen, buffered, getContentType,
	Alert(..), AlertLevel(..), AlertDescription(..), alertVersion, processAlert,
	tCheckName,
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
import qualified Crypto.PubKey.RSA as RSA

import Data.HandleLike

import TlsIo
import Types

data TlsClient = TlsClient {
	tlsNames :: [String],
	tlsVersion :: MSVersion,
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

instance HandleLike TlsClient where
	hlPut = tPut
	hlGet = tGet
	hlGetLine = tGetLine
	hlGetContent = tGetContent
	hlClose = tClose

runOpen :: Handle -> RSA.PrivateKey -> TlsIo cnt [String] -> IO TlsClient
runOpen cl pk opn = do
	ep <- createEntropyPool
	(ns, tlss) <- opn `runTlsIo` initTlsState ep cl pk
	tvgen <- atomically . newTVar $ tlssRandomGen tlss
	tvcsn <- atomically . newTVar $ tlssClientSequenceNumber tlss
	tvssn <- atomically . newTVar $ tlssServerSequenceNumber tlss
	tvbfr <- atomically $ newTVar ""
	return TlsClient {
		tlsNames = ns,
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

tCheckName :: TlsClient -> String -> Bool
tCheckName TlsClient{ tlsNames = ns } n = n `elem` ns

tPut :: TlsClient -> BS.ByteString -> IO ()
tPut ts = tPutWithCT ts ContentTypeApplicationData

tPutWithCT :: TlsClient -> ContentType -> BS.ByteString -> IO ()
tPutWithCT ts ct msg = case (vr, cs) of
	(TLS12, TLS_RSA_WITH_AES_128_CBC_SHA) -> do
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
	(vr, cs, h) = vrcsh ts
	key = tlsServerWriteKey ts
	mk = tlsServerWriteMacKey ts
	v = Version 3 3
	tvsn = tlsServerSequenceNumber ts
	tvgen = tlsRandomGen ts
	enc gen sn = encryptMessage gen key sn mk ct v msg

vrcsh :: TlsClient -> (MSVersion, CipherSuite, Handle)
vrcsh tc = (tlsVersion tc, tlsCipherSuite tc, tlsHandle tc)

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
	h = tlsHandle ts

tGetWholeWithCT :: TlsClient -> IO (ContentType, BS.ByteString)
tGetWholeWithCT ts = case (vr, cs) of
	(TLS12, TLS_RSA_WITH_AES_128_CBC_SHA) -> do
		ct <- byteStringToContentType <$> BS.hGet h 1
		v <- byteStringToVersion <$> BS.hGet h 2
		enc <- BS.hGet h . byteStringToInt =<< BS.hGet h 2
		sn <- atomically $ do
			n <- readTVar tvsn
			writeTVar tvsn $ succ n
			return n
		ret <- case dec sn ct v enc of
			Right r -> return r
			Left err -> error err
		return (ct, ret)
	_ -> error "tGetWhole: not implemented"
	where
	(vr, cs, h) = vrcsh ts
	key = tlsClientWriteKey ts
	mk = tlsClientWriteMacKey ts
	tvsn = tlsClientSequenceNumber ts
	dec sn = decryptMessage key sn mk

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
	tPutWithCT tc ContentTypeAlert "\SOH\NUL"
	tGetWholeWithCT tc >>= print
	hClose h
	where
	h = tlsHandle tc
