{-# LANGUAGE OverloadedStrings, PackageImports, RankNTypes, TupleSections,
	FlexibleContexts #-}

module HM (
	HandshakeM, runHandshakeM, HandshakeState, initHandshakeState, randomGen,
	read, write, randomByteString, updateHash, handshakeHash,
	updateSequenceNumber,
	getContentType, buffered, withRandom, debugCipherSuite,

	Partner(..), Alert(..), AlertLevel(..), AlertDescription(..),
	ContentType, CipherSuite(..), KeyExchange(..), BulkEncryption(..),
	
	Keys(..), nullKeys, cipherSuite,
	flushCipherSuite,

	TlsHandle, mkTlsHandle, getHandle,
) where

import HandshakeState2

import Prelude hiding (read)

import "monads-tf" Control.Monad.State
import "monads-tf" Control.Monad.Error
import "monads-tf" Control.Monad.Error.Class
import Data.Maybe
import Data.Word
import Data.String
import Data.HandleLike
import "crypto-random" Crypto.Random

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

import CipherSuite
-- import ContentType

type HandshakeM h gen = ErrorT Alert (StateT (HandshakeState h gen) (HandleMonad h))

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
write th dat = lift . lift . flip hlPut dat $ getHandle th

type TlsHandle h = h

nullKeys :: Keys
nullKeys = Keys {
	kCachedCipherSuite = CipherSuite KE_NULL BE_NULL,
	kClientCipherSuite = CipherSuite KE_NULL BE_NULL,
	kServerCipherSuite = CipherSuite KE_NULL BE_NULL,

	kMasterSecret = "",
	kClientWriteMacKey = "",
	kServerWriteMacKey = "",
	kClientWriteKey = "",
	kServerWriteKey = "" }

data Keys = Keys {
	kCachedCipherSuite :: CipherSuite,
	kClientCipherSuite :: CipherSuite,
	kServerCipherSuite :: CipherSuite,

	kMasterSecret :: BS.ByteString,
	kClientWriteMacKey :: BS.ByteString,
	kServerWriteMacKey :: BS.ByteString,
	kClientWriteKey :: BS.ByteString,
	kServerWriteKey :: BS.ByteString }

mkTlsHandle :: h -> TlsHandle h
mkTlsHandle = id

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

instance Error Alert where
	strMsg = NotDetected

instance IsString Alert where
	fromString = NotDetected

randomByteString :: (HandleLike h, CPRG gen) => Int -> HandshakeM h gen BS.ByteString
randomByteString len = do
	gen <- gets randomGen
	let (r, gen') = cprgGenerate len gen
	modify $ setRandomGen gen'
	return r

flushCipherSuite :: Partner -> Keys -> Keys
flushCipherSuite p k@Keys{ kCachedCipherSuite = cs } = case p of
	Client -> k { kClientCipherSuite = cs }
	Server -> k { kServerCipherSuite = cs }

data Partner = Server | Client deriving (Show, Eq)

read :: HandleLike h => TlsHandle h -> Int -> HandshakeM h gen BS.ByteString
read h n = do
	r <- lift . lift . flip hlGet n $ getHandle h
	if BS.length r == n
		then return r
		else throwError . strMsg $ "Basic.read: bad reading: " ++
			show (BS.length r) ++ " " ++ show n

updateHash :: HandleLike h => BS.ByteString -> HandshakeM h gen ()
updateHash = modify . updateHandshakeHash

handshakeHash :: HandleLike h => HandshakeM h gen BS.ByteString
handshakeHash = gets getHandshakeHash

getContentType :: HandleLike h => ((Word8, Word8) -> Bool)
	-> HandshakeM h gen (ContentType, (Word8, Word8), BS.ByteString)
	-> HandshakeM h gen ContentType
getContentType vc rd = do
	mct <- fst `liftM` gets byteStringBuffer
	(\gt -> maybe gt return mct) $ do
		(ct, v, bf) <- rd
		unless (vc v) . throwError $ Alert
			AlertLevelFatal
			AlertDescriptionProtocolVersion
			"readByteString: bad Version"
		modify $ setByteStringBuffer (Just ct, bf)
		return ct


buffered :: HandleLike h =>
	Int -> HandshakeM h gen (ContentType, BS.ByteString) ->
	HandshakeM h gen (ContentType, BS.ByteString)
buffered n rd = do
	(mct, bf) <- gets byteStringBuffer
	if BS.length bf >= n
	then do	let (ret, bf') = BS.splitAt n bf
		modify . setByteStringBuffer $
			if BS.null bf' then (Nothing, "") else (mct, bf')
		return (fromJust mct, ret)
	else do	(ct', bf') <- rd
		unless (maybe True (== ct') mct) .
			throwError . strMsg $ "Content Type confliction\n" ++
				"\tExpected: " ++ show mct ++ "\n" ++
				"\tActual  : " ++ show ct' ++ "\n" ++
				"\tData    : " ++ show bf'
		when (BS.null bf') $ throwError "buffered: No data available"
		modify $ setByteStringBuffer (Just ct', bf')
		((ct' ,) . (bf `BS.append`) . snd) `liftM` buffered (n - BS.length bf) rd

updateSequenceNumber :: HandleLike h =>
	Partner -> Keys -> HandshakeM h gen Word64
updateSequenceNumber partner ks = do
	tlss <- get
	let	sn = ($ tlss) $ case partner of
			Client -> clientSequenceNumber
			Server -> serverSequenceNumber
		cs = cipherSuite partner ks
	case cs of
		CipherSuite _ BE_NULL -> return ()
		_ -> case partner of
			Client -> modify succClientSequenceNumber
			Server -> modify succServerSequenceNumber
	return sn

cipherSuite :: Partner -> Keys -> CipherSuite
cipherSuite p = case p of
	Client -> kClientCipherSuite
	Server -> kServerCipherSuite

withRandom :: HandleLike h => (gen -> (a, gen)) -> HandshakeM h gen a
withRandom p = do
	gen <- gets randomGen
	let (x, gen') = p gen
	modify $ setRandomGen gen'
	return x

getHandle :: HandleLike h => TlsHandle h -> h
getHandle = id

debugCipherSuite :: HandleLike h =>
	TlsHandle h -> Keys -> String -> HandshakeM h gen ()
debugCipherSuite th k a = do
	let h = getHandle th
	lift . lift . hlDebug h 5 . BSC.pack
		. (++ (" - VERIFY WITH " ++ a ++ "\n")) . lenSpace 50
		. show $ kCachedCipherSuite k
	where
	lenSpace n str = str ++ replicate (n - length str) ' '
