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
	TlsIo, liftIO,

	throwError, catchError,
	updateSequenceNumber,
	randomByteString,
	clientVerifyHash,

	TlsClient, runOpen, Alert(..), AlertLevel(..), AlertDescription(..),
	tCheckName,
) where

import Prelude hiding (read)

import Control.Applicative
import Control.Monad
import qualified Data.ByteString as BS

import OpenClient

readBufferContentType :: (Version -> Bool) -> TlsIo cnt ContentType
readBufferContentType vc =
	getContentType vc $ (\(Fragment ct v bs) -> (ct, v, bs)) <$> readFragmentNoHash

readByteString ::
	(Version -> Bool) -> Int -> TlsIo cnt (ContentType, BS.ByteString)
readByteString vc n = buffered n $ do
	Fragment ct v bs <- readFragmentNoHash
	liftIO . putStrLn $ "VERSION: " ++ show v
	unless (vc v) $ throwError alertVersion
	return (ct, bs)

readFragment :: TlsIo cnt Fragment
readFragment = do
	RawFragment ct v ebody <- readRawFragment
	when (BS.null ebody) $ throwError "readFragment: ebody is null"
	body <- tlsDecryptMessage ct v ebody
	case ct of
		ContentTypeHandshake -> updateHash body
		_ -> return ()
	return $ Fragment ct v body

readFragmentNoHash :: TlsIo cnt Fragment
readFragmentNoHash = do
	RawFragment ct v ebody <- readRawFragment
	body <- tlsDecryptMessage ct v ebody
	return $ Fragment ct v body

fragmentUpdateHash :: Fragment -> TlsIo cnt ()
fragmentUpdateHash (Fragment ContentTypeHandshake _ b) = updateHash b
fragmentUpdateHash _ = return ()

writeFragment :: Fragment -> TlsIo cnt ()
writeFragment (Fragment ct v bs) =
	writeRawFragment . RawFragment ct v =<< tlsEncryptMessage ct v bs

readRawFragment :: TlsIo cnt RawFragment
readRawFragment = RawFragment <$> readContentType <*> readVersion <*> readLen 2

writeRawFragment :: RawFragment -> TlsIo cnt ()
writeRawFragment (RawFragment ct v bs) =
	writeContentType ct >> writeVersion v >> writeLen 2 bs
	
data RawFragment
	= RawFragment ContentType Version BS.ByteString
	deriving Show
