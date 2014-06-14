{-# LANGUAGE OverloadedStrings, PackageImports, FlexibleContexts #-}

module Fragment (
	ContentType(..),
	readContentType,
	readByteString,
	writeByteString,
	updateHash,

	setClientRandom, setServerRandom,
	setVersion,
	getClientRandom, getServerRandom, getKeyExchange, getBulkEncryption,
	debugCipherSuite,
	cacheCipherSuite, flushCipherSuite,

	getRandoms, saveKeys, generateKeys_,
	getMasterSecret,
	finishedHash_,

	Partner(..),
	HandshakeM, liftIO,

	updateSequenceNumber,
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

readContentType :: HandleLike h => ((Word8, Word8) -> Bool) -> HandshakeM h gen ContentType
readContentType vc = getContentType vc readFragment

readByteString :: HandleLike h =>
	((Word8, Word8) -> Bool) -> Int -> HandshakeM h gen (ContentType, BS.ByteString)
readByteString vc n = do
	(ct, bs) <- buffered n $ do
		(t, v, b) <- readFragment
		unless (vc v) $ throwError alertVersion
		return (t, b)
	case ct of
		ContentTypeHandshake -> updateHash bs
		_ -> return ()
	return (ct, bs)

readFragment :: HandleLike h => HandshakeM h gen (ContentType, (Word8, Word8), BS.ByteString)
readFragment = do
	ct <- (either error id . B.fromByteString) `liftM` read 1
	[vmjr, vmnr] <- BS.unpack `liftM` read 2
--	Version vmjr vmnr <- (either error id . B.fromByteString) `liftM` read 2
	let v = (vmjr, vmnr)
	ebody <- read . either error id . B.fromByteString =<< read 2
	when (BS.null ebody) $ throwError "readFragment: ebody is null"
	body <- tlsDecryptMessage ct ebody
--	let bs' = BS.concat [
--		B.toByteString ct,
--		B.toByteString vmjr,
--		B.toByteString vmnr,
--		body ]
--	case ct of
--		ContentTypeHandshake -> updateHash bs'
--		_ -> return ()
	return (ct, v, body)

writeByteString :: (HandleLike h, CPRG gen) =>
	ContentType -> BS.ByteString -> HandshakeM h gen ()
writeByteString ct bs = do
	enc <- tlsEncryptMessage ct bs
	case ct of
		ContentTypeHandshake -> updateHash bs
		_ -> return ()
	write $ BS.concat [
		B.toByteString ct,
		B.toByteString (3 :: Word8),
		B.toByteString (3 :: Word8),
		B.toByteString (fromIntegral $ BS.length enc :: Word16), enc ]

tlsEncryptMessage :: (HandleLike h, CPRG gen) =>
	ContentType -> BS.ByteString -> HandshakeM h gen BS.ByteString
tlsEncryptMessage ct msg = ifEnc Server msg $ \m -> do
	CipherSuite _ be <- cipherSuite Server
	(wk, mk, sn) <- getServerWrite
	hs <- case be of
		AES_128_CBC_SHA -> return hashSha1
		AES_128_CBC_SHA256 -> return hashSha256
		_ -> throwError "bad"
	let enc = encryptMessage hs wk mk sn
		(B.toByteString ct `BS.append` "\x03\x03") m
	withRandom enc

tlsDecryptMessage :: HandleLike h =>
	ContentType -> BS.ByteString -> HandshakeM h gen BS.ByteString
tlsDecryptMessage ct enc = ifEnc Client enc $ \e -> do
	CipherSuite _ be <- cipherSuite Client
	(wk, mk, sn) <- getClientWrite
	hs <- case be of
		AES_128_CBC_SHA -> return hashSha1
		AES_128_CBC_SHA256 -> return hashSha256
		_ -> throwError "bad"
	eitherToError $ decryptMessage hs wk mk sn
		(B.toByteString ct `BS.append` "\x03\x03") e

eitherToError :: (Show msg, MonadError m, Error (ErrorType m)) => Either msg a -> m a
eitherToError = either (throwError . strMsg . show) return
