{-# LANGUAGE OverloadedStrings, PackageImports, RankNTypes, TupleSections,
	FlexibleContexts, TypeFamilies #-}

module HM (
	HandshakeM, runHm, runHandshakeM, handshakeM,
	HandshakeState, initHandshakeState,
	read, write, randomByteString, updateHash, handshakeHash,
	updateSequenceNumber,
	getContentType, buffered, withRandom, debugCipherSuite,

	Partner(..), Alert(..), AlertLevel(..), AlertDescription(..),
	CipherSuite(..), KeyExchange, BulkEncryption(..),
	
	Keys(..), nullKeys, cipherSuite,
	flushCipherSuite,

	TlsHandle, mkTlsHandle, getHandle,

	ErrorType, Error, MonadError, throwError, lift, catchError,

	TlsClientState, initialTlsStateWithClientZero, decryptMessage,
	hashSha1, hashSha256, encryptMessage,
	ContentType(..),
	TlsClientConst(..),
	finishedHash_, clientIdZero, generateKeys_, checkName, clientName,
) where

import Prelude hiding (read)

import Control.Monad
import Data.Maybe
import Data.Word
import Data.HandleLike
import "crypto-random" Crypto.Random

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

import HmMonad
import CryptoTools

import qualified Codec.Bytable as B
import System.IO

runHm :: HandleLike h => TlsHandle h ->
	HandshakeM h gen a -> HandshakeState h gen ->
	HandleMonad h (a, HandshakeState h gen)
runHm th io st = do
	(ret, st') <- (io `catchError` processAlert th) `runHandshakeM` st
	case ret of
		Right r -> return (r, st')
		Left err -> error $ show err

processAlert :: HandleLike h =>
	TlsHandle h -> Alert -> HandshakeM h gen a
processAlert th alt = do
	write th $ alertToByteString alt
	throwError alt

write :: HandleLike h => TlsHandle h ->
	BS.ByteString -> HandleLike h => HandshakeM h gen ()
write th dat = flip thlPut dat $ getHandle th

type TlsHandle h = h

mkTlsHandle :: h -> TlsHandle h
mkTlsHandle = id

randomByteString :: (HandleLike h, CPRG gen) => Int -> HandshakeM h gen BS.ByteString
randomByteString len = withRandom $ cprgGenerate len

flushCipherSuite :: Partner -> Keys -> Keys
flushCipherSuite p k@Keys{ kCachedCipherSuite = cs } = case p of
	Client -> k { kClientCipherSuite = cs }
	Server -> k { kServerCipherSuite = cs }

data Partner = Server | Client deriving (Show, Eq)

read :: HandleLike h => TlsHandle h -> Int -> HandshakeM h gen BS.ByteString
read h n = do
	r <- flip thlGet n $ getHandle h
	if BS.length r == n
		then return r
		else throwError . strToAlert $ "Basic.read: bad reading: " ++
			show (BS.length r) ++ " " ++ show n

updateHash :: HandleLike h => BS.ByteString -> HandshakeM h gen ()
updateHash = updateH clientIdZero

handshakeHash :: HandleLike h => HandshakeM h gen BS.ByteString
handshakeHash = getHash clientIdZero

getContentType :: HandleLike h => ((Word8, Word8) -> Bool)
	-> HandshakeM h gen (ContentType, (Word8, Word8), BS.ByteString)
	-> HandshakeM h gen ContentType
getContentType vc rd = do
	mct <- fst `liftM` getBuf clientIdZero
	(\gt -> maybe gt return mct) $ do
		(ct, v, bf) <- rd
		unless (vc v) . throwError $ Alert
			AlertLevelFatal
			AlertDescriptionProtocolVersion
			"readByteString: bad Version"
		setBuf clientIdZero (Just ct, bf)
		return ct


buffered :: HandleLike h =>
	Int -> HandshakeM h gen (ContentType, BS.ByteString) ->
	HandshakeM h gen (ContentType, BS.ByteString)
buffered n rd = do
	(mct, bf) <- getBuf clientIdZero
	if BS.length bf >= n
	then do	let (ret, bf') = BS.splitAt n bf
		setBuf clientIdZero $
			if BS.null bf' then (Nothing, "") else (mct, bf')
		return (fromJust mct, ret)
	else do	(ct', bf') <- rd
		unless (maybe True (== ct') mct) .
			throwError . strToAlert $ "Content Type confliction\n" ++
				"\tExpected: " ++ show mct ++ "\n" ++
				"\tActual  : " ++ show ct' ++ "\n" ++
				"\tData    : " ++ show bf'
		when (BS.null bf') $ throwError "buffered: No data available"
		setBuf clientIdZero (Just ct', bf')
		((ct' ,) . (bf `BS.append`) . snd) `liftM` buffered (n - BS.length bf) rd

updateSequenceNumber :: HandleLike h =>
	Partner -> Keys -> HandshakeM h gen Word64
updateSequenceNumber partner ks = do
	sn <- case partner of
		Client -> getClientSn clientIdZero
		Server -> getServerSn clientIdZero
	let	cs = cipherSuite partner ks
	case cs of
		CipherSuite _ BE_NULL -> return ()
		_ -> case partner of
			Client -> succClientSn clientIdZero
			Server -> succServerSn clientIdZero
	return sn

cipherSuite :: Partner -> Keys -> CipherSuite
cipherSuite p = case p of
	Client -> kClientCipherSuite
	Server -> kServerCipherSuite

getHandle :: HandleLike h => TlsHandle h -> h
getHandle = id

debugCipherSuite :: HandleLike h =>
	TlsHandle h -> Keys -> String -> HandshakeM h gen ()
debugCipherSuite th k a = do
	let h = getHandle th
	thlDebug h 5 . BSC.pack
		. (++ (" - VERIFY WITH " ++ a ++ "\n")) . lenSpace 50
		. show $ kCachedCipherSuite k
	where
	lenSpace n str = str ++ replicate (n - length str) ' '

type HandshakeState h gen = TlsClientState h gen

initHandshakeState :: gen -> HandshakeState h gen
initHandshakeState = 
	(\(i, s) -> if i == clientIdZero
		then s
		else error "HandshakeState.initHandshakeState")
	. newClientId . initialTlsState

data TlsClientConst h g = TlsClientConst {
	clientId :: ClientId,
	tlsNames :: [String],
	tlsHandle :: h,
	keys :: Keys }

type family HandleRandomGen h

type instance HandleRandomGen Handle = SystemRNG

instance (HandleLike h, CPRG g) =>
	HandleLike (TlsClientConst h g) where
	type HandleMonad (TlsClientConst h g) = HandshakeM h g
	hlPut = tPutSt
	hlGet = tGetSt
	hlGetLine = tGetLineSt
	hlGetContent = tGetContentSt
	hlClose = tCloseSt

checkName :: TlsClientConst h g -> String -> Bool
checkName tc n = n `elem` tlsNames tc

clientName :: TlsClientConst h g -> Maybe String
clientName = listToMaybe . tlsNames 

tPutSt :: (HandleLike h, CPRG gen) => TlsClientConst h gen ->
	BS.ByteString -> HandshakeM h gen ()
tPutSt tc = tPutWithCtSt tc ContentTypeApplicationData

tPutWithCtSt :: (HandleLike h, CPRG gen) =>
	TlsClientConst h gen -> ContentType -> BS.ByteString ->
	HandshakeM h gen ()
tPutWithCtSt tc ct msg = do
	hs <- case cs of
		CipherSuite _ AES_128_CBC_SHA -> return hashSha1
		CipherSuite _ AES_128_CBC_SHA256 -> return hashSha256
		_ -> error "OpenClient.tPutWithCT"
	sn <- getServerSn $ clientId tc
	ebody <- withRandom $ flip (enc hs) sn
	succServerSn $ clientId tc
	thlPut h $ BS.concat [
		B.toByteString ct, "\x03\x03",
		B.addLength (undefined :: Word16) ebody ]
	where
	(cs, h) = vrcshSt tc
	key = kServerWriteKey $ keys tc -- tlsServerWriteKey tc
	mk = kServerWriteMacKey $ keys tc -- tlsServerWriteMacKey tc
	enc hs gen sn = encryptMessage hs key mk sn
		(B.toByteString ct `BS.append` "\x03\x03") msg gen

vrcshSt :: TlsClientConst h gen -> (CipherSuite, h)
-- vrcshSt tc = (tlsCipherSuite tc, tlsHandle tc)
vrcshSt tc = (kCachedCipherSuite $ keys tc, tlsHandle tc)

tGetWholeSt :: (HandleLike h, CPRG gen) =>
	TlsClientConst h gen -> HandshakeM h gen BS.ByteString
tGetWholeSt tc = do
	ret <- tGetWholeWithCtSt tc
	case ret of
		(ContentTypeApplicationData, ad) -> return ad
		(ContentTypeAlert, "\SOH\NUL") -> do
			tPutWithCtSt tc ContentTypeAlert "\SOH\NUL"
			thlError h "tGetWholeSt: EOF"
		_ -> do	tPutWithCtSt tc ContentTypeAlert "\2\10"
			error "not application data"
	where
	h = tlsHandle tc

tGetWholeWithCtSt :: HandleLike h => TlsClientConst h gen ->
	HandshakeM h gen (ContentType, BS.ByteString)
tGetWholeWithCtSt tc = do
	hs <- case cs of
		CipherSuite _ AES_128_CBC_SHA -> return hashSha1
		CipherSuite _ AES_128_CBC_SHA256 -> return hashSha256
		_ -> thlError h "OpenClient.tGetWholeWithCT"
	ct <- (either error id . B.fromByteString) `liftM` thlGet h 1
	[_vmjr, _vmnr] <- BS.unpack `liftM` thlGet h 2
	enc <- thlGet h . either error id . B.fromByteString
		=<< thlGet h 2
	sn <- getClientSn $ clientId tc
	succClientSn $ clientId tc
	if BS.null enc then return (ct, "") else do
		ret <- case dec hs sn (B.toByteString ct `BS.append` "\x03\x03") enc of
			Right r -> return r
			Left err -> error err
		return (ct, ret)
	where
	(cs, h) = vrcshSt tc
	key = kClientWriteKey $ keys tc
	mk = kClientWriteMacKey $ keys tc
	dec hs = decryptMessage hs key mk

tGetSt :: (HandleLike h, CPRG gen) => TlsClientConst h gen ->
	Int -> HandshakeM h gen BS.ByteString
tGetSt tc n = do
	(mct, bfr) <- getBuf $ clientId tc
	if n <= BS.length bfr then do
		let (ret, bfr') = BS.splitAt n bfr
		setBuf (clientId tc) (mct, bfr')
		return ret
	else do	msg <- tGetWholeSt tc
		setBuf (clientId tc) (Just ContentTypeApplicationData, msg)
		(bfr `BS.append`) `liftM` tGetSt tc (n - BS.length bfr)

tGetLineSt :: (HandleLike h, CPRG gen) =>
	TlsClientConst h gen -> HandshakeM h gen BS.ByteString
tGetLineSt tc = do
	(mct, bfr) <- getBuf $ clientId tc
	case splitOneLine bfr of
		Just (l, ls) -> do
			setBuf (clientId tc) (mct, ls)
			return l
		_ -> do	msg <- tGetWholeSt tc
			setBuf (clientId tc) (Just ContentTypeApplicationData, msg)
			(bfr `BS.append`) `liftM` tGetLineSt tc

tGetContentSt :: (HandleLike h, CPRG gen) =>
	TlsClientConst h gen -> HandshakeM h gen BS.ByteString
tGetContentSt tc = do
	(_, bfr) <- getBuf $ clientId tc
	if BS.null bfr then tGetWholeSt tc else do
		setBuf (clientId tc) (Nothing, BS.empty)
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

tCloseSt :: (HandleLike h, CPRG gen) =>
	TlsClientConst h gen -> HandshakeM h gen ()
tCloseSt tc = do
	tPutWithCtSt tc ContentTypeAlert "\SOH\NUL"
	thlClose h
	where
	h = tlsHandle tc
