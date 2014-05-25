{-# LANGUAGE OverloadedStrings #-}

module Fragment (
	Fragment(..), RawFragment(..), ContentType(..), Version,
	readBufferContentType, readByteString,
	readFragment, readFragmentNoHash, fragmentUpdateHash, writeFragment,
	readRawFragment, writeRawFragment,

	setClientRandom, setServerRandom, setVersion,
	cacheCipherSuite, flushCipherSuite,
	generateKeys,

	decryptRSA, finishedHash,

	Partner(..),
	TlsIo, evalTlsIo, liftIO,

	throwError, catchError,
	updateSequenceNumber,
	randomByteString,
	readCached,
	clientVerifyHash,

	TlsClient, runOpen, Alert,
) where

import Prelude hiding (read)

import Control.Applicative
import Control.Monad
import qualified Data.ByteString as BS

import TlsIo

readBufferContentType :: TlsIo cnt ContentType
readBufferContentType =
	getContentType $ (\(Fragment ct _ bs) -> (ct, bs)) <$> readFragmentNoHash

readByteString ::
	(Version -> Bool) -> Int -> TlsIo cnt (ContentType, BS.ByteString)
readByteString vc n = buffered n $ do
	Fragment ct v bs <- readFragmentNoHash
	unless (vc v) $ throwError "readByteString: bad Version"
	return (ct, bs)

readFragment :: TlsIo cnt Fragment
readFragment = do
	RawFragment ct v ebody <- readRawFragment
	when (BS.null ebody) $ throwError "readFragment: ebody is null"
	body <- decryptMessage ct v ebody
	case ct of
		ContentTypeHandshake -> updateHash body
		_ -> return ()
	return $ Fragment ct v body

readFragmentNoHash :: TlsIo cnt Fragment
readFragmentNoHash = do
	RawFragment ct v ebody <- readRawFragment
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
