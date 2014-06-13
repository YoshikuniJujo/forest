{-# LANGUAGE OverloadedStrings, PackageImports #-}

module Fragment (
	ContentType(..),
	readContentType,
	readByteString,
	writeByteString,
	updateHash,

	setClientRandom, setServerRandom,
	setVersion,
	getClientRandom, getServerRandom, getCipherSuite,
	cacheCipherSuite, flushCipherSuite,
	generateKeys,

	decryptRSA, finishedHash,

	Partner(..),
	HandshakeM, liftIO,

	updateSequenceNumber,
	randomByteString,
	clientVerifyHash,
	clientVerifyHashEc,

	Alert(..), AlertLevel(..), AlertDescription(..),
	checkName, clientName,
	runOpen,
	TlsClientConst,
	TlsClientState,
	initialTlsState,

	withRandom,
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

readContentType :: HandleLike h => ((Word8, Word8) -> Bool) -> HandshakeM h gen ContentType
readContentType vc = getContentType vc readFragment

readByteString :: HandleLike h =>
	((Word8, Word8) -> Bool) -> Int -> HandshakeM h gen (ContentType, BS.ByteString)
readByteString vc n = buffered n $ do
	(ct, v@(vmjr, vmnr), bs) <- readFragment
	unless (vc v) $ throwError alertVersion
	let bs' = BS.concat [
		B.toByteString ct,
		B.toByteString vmjr,
		B.toByteString vmnr,
		bs ]
	case ct of
		ContentTypeHandshake -> updateHash bs' >> updateHash bs'
		_ -> updateHash bs' -- return ()
	return (ct, bs)

readFragment :: HandleLike h => HandshakeM h gen (ContentType, (Word8, Word8), BS.ByteString)
readFragment = do
	ct <- (either error id . B.fromByteString) `liftM` read 1
	[vmjr, vmnr] <- BS.unpack `liftM` read 2
--	Version vmjr vmnr <- (either error id . B.fromByteString) `liftM` read 2
	let v = (vmjr, vmnr)
	ebody <- read . either error id . B.fromByteString =<< read 2
	when (BS.null ebody) $ throwError "readFragment: ebody is null"
	body <- tlsDecryptMessage ct v ebody
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
	enc <- tlsEncryptMessage ct (3, 3) bs
	let bs' = BS.concat [
		B.toByteString ct,
		B.toByteString (3 :: Word8),
		B.toByteString (3 :: Word8),
		B.toByteString (fromIntegral $ BS.length enc :: Word16), enc ]
	write bs'
--	case ct of
--		ContentTypeHandshake -> updateHash bs'
--		_ -> return ()
