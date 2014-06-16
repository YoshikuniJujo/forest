{-# LANGUAGE OverloadedStrings, PackageImports, RankNTypes, TupleSections,
	FlexibleContexts #-}

module HM (
	HandshakeM, runHandshakeM, HandshakeState, initHandshakeState,
	read, write, randomByteString, updateHash, handshakeHash,
	updateSequenceNumber,
	getContentType, buffered, withRandom, debugCipherSuite,

	Partner(..), Alert(..), AlertLevel(..), AlertDescription(..),
	ContentType, CipherSuite(..), KeyExchange, BulkEncryption(..),
	
	Keys(..), nullKeys, cipherSuite,
	flushCipherSuite,

	TlsHandle, mkTlsHandle, getHandle,

	throwError, ErrorType, Error, MonadError, catchError,
	StateT(..),
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

runHandshakeM :: HandleLike h => TlsHandle h ->
	HandshakeM h gen a -> HandshakeState h gen ->
	HandleMonad h (a, HandshakeState h gen)
runHandshakeM th io st = do
	(ret, st') <- runErrorT (io `catchError` processAlert th)
		`runStateT` st
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
