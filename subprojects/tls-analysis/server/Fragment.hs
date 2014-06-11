{-# LANGUAGE OverloadedStrings, PackageImports #-}

module Fragment (
	readBufContentType,
	readByteString,
	writeByteString,
	updateHash,

	setClientRandom, setServerRandom, setVersion,
	getClientRandom, getServerRandom, getCipherSuite,
	cacheCipherSuite, flushCipherSuite,
	generateKeys,

	decryptRSA, finishedHash,

	Partner(..),
	TlsIo, liftIO,

	throwError, catchError,
	updateSequenceNumber,
	randomByteString,
	clientVerifyHash,
	clientVerifyHashEc,

	TlsClient(..), runOpen, Alert(..), AlertLevel(..), AlertDescription(..),
	checkName, getName,
	runOpenSt,
	TlsClientConst,
	TlsClientState,
	initialTlsState,

	isEphemeralDH,
	getRandomGen,
	putRandomGen,
	getHandle,
) where

import Prelude hiding (read)

import Control.Monad
import qualified Data.ByteString as BS

import OpenClient

import "crypto-random" Crypto.Random

import Data.HandleLike

import qualified Codec.Bytable as B
import Data.Word

readBufContentType :: HandleLike h => (Version -> Bool) -> TlsIo h gen ContentType
readBufContentType vc = getContentType vc readFragment

readByteString :: HandleLike h =>
	(Version -> Bool) -> Int -> TlsIo h gen (ContentType, BS.ByteString)
readByteString vc n = buffered n $ do
	(ct, v, bs) <- readFragment
	unless (vc v) $ throwError alertVersion
	return (ct, bs)

readFragment :: HandleLike h => TlsIo h gen (ContentType, Version, BS.ByteString)
readFragment = do
	ct <- byteStringToContentType `liftM` read 1
	v <- byteStringToVersion `liftM` read 2
	ebody <- read . either error id . B.fromByteString =<< read 2
	when (BS.null ebody) $ throwError "readFragment: ebody is null"
	body <- tlsDecryptMessage ct v ebody
	return (ct, v, body)

writeByteString :: (HandleLike h, CPRG gen) =>
	ContentType -> BS.ByteString -> TlsIo h gen ()
writeByteString ct bs = do
	enc <- tlsEncryptMessage ct (Version 3 3) bs
	write $ BS.concat [
		contentTypeToByteString ct,
		versionToByteString (Version 3 3),
		B.toByteString (fromIntegral $ BS.length enc :: Word16), enc ]
--		intToByteString 2 $ BS.length enc, enc ]
