{-# LANGUAGE OverloadedStrings, PackageImports, FlexibleContexts #-}

module Fragment (
	TlsHandle,
	mkTlsHandle,
	ContentType(..),
	readContentType,
	readByteString,
	writeByteString,
	updateHash,

	debugCipherSuite,
	flushCipherSuite,

	generateKeys_,
	finishedHash_,

	Partner(..),
	HandshakeM, liftIO,

	randomByteString,
	handshakeHash,

	Alert(..), AlertLevel(..), AlertDescription(..),
	checkName, clientName,
	runOpen,
	TlsClientConst,
	TlsClientState,
	initialTlsState,

	withRandom,
	getHandle,
	eitherToError,
	Keys(..), nullKeys,
) where

import Prelude hiding (read)

import Control.Monad
import qualified Data.ByteString as BS

import OpenClient

import "crypto-random" Crypto.Random
import "monads-tf" Control.Monad.Error
import "monads-tf" Control.Monad.Error.Class

import Data.HandleLike

import qualified Codec.Bytable as B
import Data.Word

readContentType :: HandleLike h => TlsHandle h -> Keys ->
	((Word8, Word8) -> Bool) -> HandshakeM h gen ContentType
readContentType th ks vc = getContentType vc $ readFragment th ks

readByteString :: HandleLike h => TlsHandle h -> Keys ->
	((Word8, Word8) -> Bool) -> Int -> HandshakeM h gen (ContentType, BS.ByteString)
readByteString th ks vc n = do
	(ct, bs) <- buffered n $ do
		(t, v, b) <- readFragment th ks
		unless (vc v) . throwError $ Alert
			AlertLevelFatal
			AlertDescriptionProtocolVersion
			"Fragment.readByteString: bad Version"
		return (t, b)
	case ct of
		ContentTypeHandshake -> updateHash bs
		_ -> return ()
	return (ct, bs)

readFragment :: HandleLike h => TlsHandle h -> Keys ->
	HandshakeM h gen (ContentType, (Word8, Word8), BS.ByteString)
readFragment th ks = do
	ct <- (either error id . B.fromByteString) `liftM` read th 1
	[vmjr, vmnr] <- BS.unpack `liftM` read th 2
	let v = (vmjr, vmnr)
	ebody <- read th . either error id . B.fromByteString =<< read th 2
	when (BS.null ebody) $ throwError "readFragment: ebody is null"
	body <- tlsDecryptMessage ks ct ebody
	return (ct, v, body)

writeByteString :: (HandleLike h, CPRG gen) => TlsHandle h -> Keys ->
	ContentType -> BS.ByteString -> HandshakeM h gen ()
writeByteString th ks ct bs = do
	enc <- tlsEncryptMessage ks ct bs
	case ct of
		ContentTypeHandshake -> updateHash bs
		_ -> return ()
	write th $ BS.concat [
		B.toByteString ct,
		B.toByteString (3 :: Word8),
		B.toByteString (3 :: Word8),
		B.toByteString (fromIntegral $ BS.length enc :: Word16), enc ]

tlsEncryptMessage :: (HandleLike h, CPRG gen) => Keys ->
	ContentType -> BS.ByteString -> HandshakeM h gen BS.ByteString
tlsEncryptMessage Keys{ kServerCipherSuite = CipherSuite _ BE_NULL } _ msg =
	return msg
tlsEncryptMessage ks ct msg = do
	let	CipherSuite _ be = cipherSuite Server ks
		wk = kServerWriteKey ks
		mk = kServerWriteMacKey ks
	sn <- updateSequenceNumber Server ks
	hs <- case be of
		AES_128_CBC_SHA -> return hashSha1
		AES_128_CBC_SHA256 -> return hashSha256
		_ -> throwError "bad"
	let enc = encryptMessage hs wk mk sn
		(B.toByteString ct `BS.append` "\x03\x03") msg
	withRandom enc

tlsDecryptMessage :: HandleLike h => Keys ->
	ContentType -> BS.ByteString -> HandshakeM h gen BS.ByteString
tlsDecryptMessage Keys{ kClientCipherSuite = CipherSuite _ BE_NULL } _ enc =
	return enc
tlsDecryptMessage ks ct enc = do
	let	CipherSuite _ be = cipherSuite Client ks
		wk = kClientWriteKey ks
		mk = kClientWriteMacKey ks
	sn <- updateSequenceNumber Client ks
	hs <- case be of
		AES_128_CBC_SHA -> return hashSha1
		AES_128_CBC_SHA256 -> return hashSha256
		_ -> throwError "bad"
	eitherToError $ decryptMessage hs wk mk sn
		(B.toByteString ct `BS.append` "\x03\x03") enc

eitherToError :: (Show msg, MonadError m, Error (ErrorType m)) => Either msg a -> m a
eitherToError = either (throwError . strMsg . show) return
