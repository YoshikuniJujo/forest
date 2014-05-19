{-# LANGUAGE OverloadedStrings #-}

module Fragment (
	Fragment(..), RawFragment(..), ContentType(..), Version,
	readFragment, readFragmentNoHash, fragmentUpdateHash, writeFragment,
	readRawFragment, writeRawFragment,

--	clientWriteMacKey,

	setClientRandom, setServerRandom, setVersion,
	cacheCipherSuite, flushCipherSuite,
	generateKeys,

	decryptRSA, finishedHash,
--	encryptRSA,
	
--	masterSecret,

--	debugPrintKeys,
--	debugShowKeys,

	Partner(..),
	TlsIo, evalTlsIo, liftIO,

	throwError,
	updateSequenceNumber,
	randomByteString,
	readCached,
	clientVerifyHash,

	runOpen, tPut, tGetWhole,
) where

import Prelude hiding (read)

import Control.Applicative
import qualified Data.ByteString as BS

import TlsIo
import Basic

readFragment :: TlsIo cnt Fragment
readFragment = do
	RawFragment ct v ebody <- readRawFragment
--	body <- decryptBody ct v ebody
	body <- decryptMessage ct v ebody
	case ct of
		ContentTypeHandshake -> updateHash body
		_ -> return ()
	return $ Fragment ct v body

readFragmentNoHash :: TlsIo cnt Fragment
readFragmentNoHash = do
	RawFragment ct v ebody <- readRawFragment
--	body <- decryptBody ct v ebody
	body <- decryptMessage ct v ebody
	return $ Fragment ct v body

fragmentUpdateHash :: Fragment -> TlsIo cnt ()
fragmentUpdateHash (Fragment ContentTypeHandshake _ b) = updateHash b
fragmentUpdateHash _ = return ()

writeFragment :: Fragment -> TlsIo cnt ()
writeFragment (Fragment ct v bs) =
	writeRawFragment . RawFragment ct v =<< encryptMessage ct v bs

readRawFragment :: TlsIo cnt RawFragment
readRawFragment = RawFragment <$> readContentType <*> readVersion <*> readLen 2

writeRawFragment :: RawFragment -> TlsIo cnt ()
writeRawFragment (RawFragment ct v bs) =
	writeContentType ct >> writeVersion v >> writeLen 2 bs
	
data RawFragment
	= RawFragment ContentType Version BS.ByteString
	deriving Show
