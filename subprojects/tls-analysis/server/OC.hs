{-# LANGUAGE PackageImports, OverloadedStrings, TupleSections, TypeFamilies #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module OC (
	ContentType(..),
	liftIO, throwError, catchError,

	generateKeys_,
	finishedHash_,

	TlsClient(..),
	initialTlsState,

	checkName, clientName,

	encryptMessage,
	decryptMessage,
	CipherSuite(..),
	BulkEncryption(..),

	hashSha1,
	hashSha256,

	TlsClientConst(..),
	TlsClientState,

	newClientId,
	getRandomGenSt,
	setRandomGen,
) where

import Prelude hiding (read)

import Control.Concurrent.STM
import "monads-tf" Control.Monad.Error
import Data.Maybe
import Data.Word
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import System.IO
import "crypto-random" Crypto.Random

import Data.HandleLike

-- import HM
import CryptoTools
import ClientState
import qualified Codec.Bytable as B

import CipherSuite
import ContentType

import "monads-tf" Control.Monad.State

stateToStm :: StateT s IO a -> TVar s -> IO a
stateToStm m v = do
	s <- atomically $ readTVar v
	(r, s') <- m `runStateT` s
	atomically $ writeTVar v s'
	return r

toStm :: (TlsClientConst Handle SystemRNG -> StateT (TlsClientState SystemRNG) IO a) -> TlsClient -> IO a
toStm s (TlsClient tc ts) = stateToStm (s tc) ts

toStm1 :: (TlsClientConst Handle SystemRNG -> a -> StateT (TlsClientState SystemRNG) IO b) ->
	TlsClient -> a -> IO b
toStm1 s (TlsClient tc ts) x = stateToStm (s tc x) ts

data TlsClient = TlsClient {
	tlsConst :: TlsClientConst Handle SystemRNG,
	tlsState :: TVar (TlsClientState SystemRNG) }

data TlsClientConst h g = TlsClientConst {
	clientId :: ClientId,
	tlsNames :: [String],
	tlsCipherSuite :: CipherSuite,
	tlsHandle :: h,
	tlsClientWriteMacKey :: BS.ByteString,
	tlsServerWriteMacKey :: BS.ByteString,
	tlsClientWriteKey :: BS.ByteString,
	tlsServerWriteKey :: BS.ByteString }

instance HandleLike TlsClient where
	type HandleMonad TlsClient = IO
	hlPut = tPut
	hlGet = tGet
	hlGetLine = tGetLine
	hlGetContent = tGetContent
	hlClose = tClose

type family HandleRandomGen h

type instance HandleRandomGen Handle = SystemRNG

instance (HandleLike h, CPRG g) =>
	HandleLike (TlsClientConst h g) where
	type HandleMonad (TlsClientConst h g) =
		StateT (TlsClientState g) (HandleMonad h)
	hlPut = tPutSt
	hlGet = tGetSt
	hlGetLine = tGetLineSt
	hlGetContent = tGetContentSt
	hlClose = tCloseSt

checkName :: TlsClient -> String -> Bool
checkName tc n = n `elem` tlsNames (tlsConst tc)

clientName :: TlsClientConst h g -> Maybe String
clientName = listToMaybe . tlsNames 

tPut :: TlsClient -> BS.ByteString -> IO ()
tPut = toStm1 tPutSt

tGet :: TlsClient -> Int -> IO BS.ByteString
tGet = toStm1 tGetSt

tGetLine :: TlsClient -> IO BS.ByteString
tGetLine = toStm tGetLineSt

tGetContent :: TlsClient -> IO BS.ByteString
tGetContent = toStm tGetContentSt

--

tPutSt :: (HandleLike h, CPRG gen) => TlsClientConst h gen ->
	BS.ByteString -> StateT (TlsClientState gen) (HandleMonad h) ()
tPutSt tc = tPutWithCtSt tc ContentTypeApplicationData

tPutWithCtSt :: (HandleLike h, CPRG gen) =>
	TlsClientConst h gen -> ContentType -> BS.ByteString ->
	StateT (TlsClientState gen) (HandleMonad h) ()
tPutWithCtSt tc ct msg = do
	hs <- case cs of
		CipherSuite _ AES_128_CBC_SHA -> return hashSha1
		CipherSuite _ AES_128_CBC_SHA256 -> return hashSha256
		_ -> error "OpenClient.tPutWithCT"
	gen <- gets getRandomGenSt
	sn <- gets . getServerSequenceNumber $ clientId tc
	let (ebody, gen') = enc hs gen sn
	modify $ setRandomGen gen'
	modify . setServerSequenceNumber (clientId tc) $ succ sn
	lift . hlPut h $ BS.concat [
		B.toByteString ct, "\x03\x03",
		B.addLength (undefined :: Word16) ebody ]
	where
	(cs, h) = vrcshSt tc
	key = tlsServerWriteKey tc
	mk = tlsServerWriteMacKey tc
	enc hs gen sn = encryptMessage hs key mk sn
		(B.toByteString ct `BS.append` "\x03\x03") msg gen

vrcshSt :: TlsClientConst h gen -> (CipherSuite, h)
vrcshSt tc = (tlsCipherSuite tc, tlsHandle tc)

tGetWholeSt :: (HandleLike h, CPRG gen) =>
	TlsClientConst h gen -> StateT (TlsClientState gen) (HandleMonad h) BS.ByteString
tGetWholeSt tc = do
	ret <- tGetWholeWithCtSt tc
	case ret of
		(ContentTypeApplicationData, ad) -> return ad
		(ContentTypeAlert, "\SOH\NUL") -> do
			tPutWithCtSt tc ContentTypeAlert "\SOH\NUL"
			lift $ hlError h "tGetWholeSt: EOF"
		_ -> do	tPutWithCtSt tc ContentTypeAlert "\2\10"
			error "not application data"
	where
	h = tlsHandle tc

tGetWholeWithCtSt :: HandleLike h => TlsClientConst h gen ->
	StateT (TlsClientState gen) (HandleMonad h) (ContentType, BS.ByteString)
tGetWholeWithCtSt tc = do
	hs <- case cs of
		CipherSuite _ AES_128_CBC_SHA -> return hashSha1
		CipherSuite _ AES_128_CBC_SHA256 -> return hashSha256
		_ -> lift $ hlError h "OpenClient.tGetWholeWithCT"
	ct <- (either error id . B.fromByteString) `liftM` lift (hlGet h 1)
	[_vmjr, _vmnr] <- BS.unpack `liftM` lift (hlGet h 2)
	enc <- lift . hlGet h . either error id . B.fromByteString
		=<< lift (hlGet h 2)
	sn <- gets . getClientSequenceNumber $ clientId tc
	modify . setClientSequenceNumber (clientId tc) $ succ sn
	if BS.null enc then return (ct, "") else do
		ret <- case dec hs sn (B.toByteString ct `BS.append` "\x03\x03") enc of
			Right r -> return r
			Left err -> error err
		return (ct, ret)
	where
	(cs, h) = vrcshSt tc
	key = tlsClientWriteKey tc
	mk = tlsClientWriteMacKey tc
	dec hs = decryptMessage hs key mk

tGetSt :: (HandleLike h, CPRG gen) => TlsClientConst h gen ->
	Int -> StateT (TlsClientState gen) (HandleMonad h) BS.ByteString
tGetSt tc n = do
	bfr <- gets . getBuffer $ clientId tc
	if n <= BS.length bfr then do
		let (ret, bfr') = BS.splitAt n bfr
		modify $ setBuffer (clientId tc) bfr'
		return ret
	else do	msg <- tGetWholeSt tc
		modify $ setBuffer (clientId tc) msg
		(bfr `BS.append`) `liftM` tGetSt tc (n - BS.length bfr)

tGetLineSt :: (HandleLike h, CPRG gen) =>
	TlsClientConst h gen -> StateT (TlsClientState gen) (HandleMonad h) BS.ByteString
tGetLineSt tc = do
	bfr <- gets . getBuffer $ clientId tc
	case splitOneLine bfr of
		Just (l, ls) -> do
			modify $ setBuffer (clientId tc) ls
			return l
		_ -> do	msg <- tGetWholeSt tc
			modify $ setBuffer (clientId tc) msg
			(bfr `BS.append`) `liftM` tGetLineSt tc

tGetContentSt :: (HandleLike h, CPRG gen) =>
	TlsClientConst h gen -> StateT (TlsClientState gen) (HandleMonad h) BS.ByteString
tGetContentSt tc = do
	bfr <- gets . getBuffer $ clientId tc
	if BS.null bfr then tGetWholeSt tc else do
		modify $ setBuffer (clientId tc) BS.empty
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

tCloseSt :: (HandleLike h, CPRG gen) =>
	TlsClientConst h gen -> StateT (TlsClientState gen) (HandleMonad h) ()
tCloseSt tc = do
	tPutWithCtSt tc ContentTypeAlert "\SOH\NUL"
	lift $ hlClose h
	where
	h = tlsHandle tc