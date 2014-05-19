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

	ClientHandle(..),
	Partner(..),
	TlsIo, evalTlsIo, liftIO,

	throwError,
	updateSequenceNumberSmart,
	randomByteString,
	readCached,
	clientVerifyHash,
) where

import Prelude hiding (read)

import Control.Applicative
import qualified Data.ByteString as BS

import TlsIo
import Basic

readFragment :: Partner -> TlsIo cnt Fragment
readFragment p = do
	RawFragment ct v ebody <- readRawFragment
	body <- decryptBody p ct v ebody
	case ct of
		ContentTypeHandshake -> updateHash body
		_ -> return ()
	return $ Fragment ct v body

readFragmentNoHash :: Partner -> TlsIo cnt Fragment
readFragmentNoHash p = do
	RawFragment ct v ebody <- readRawFragment
	body <- decryptBody p ct v ebody
	return $ Fragment ct v body

fragmentUpdateHash :: Fragment -> TlsIo cnt ()
fragmentUpdateHash (Fragment ContentTypeHandshake _ b) = updateHash b
fragmentUpdateHash _ = return ()

writeFragment :: Fragment -> TlsIo cnt ()
writeFragment (Fragment ct v bs) =
	writeRawFragment . RawFragment ct v =<< encryptBody Server ct v bs

readRawFragment :: TlsIo cnt RawFragment
readRawFragment = RawFragment <$> readContentType <*> readVersion <*> readLen 2

writeRawFragment :: RawFragment -> TlsIo cnt ()
writeRawFragment (RawFragment ct v bs) =
	writeContentType ct >> writeVersion v >> writeLen 2 bs
	
data RawFragment
	= RawFragment ContentType Version BS.ByteString
	deriving Show
