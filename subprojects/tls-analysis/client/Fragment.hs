{-# LANGUAGE OverloadedStrings #-}

module Fragment (
	readFragment, writeFragment, fragmentUpdateHash,

	TlsIo, evalTlsIo, liftIO, throwError, readCached, randomByteString,
	Partner(..),

	setVersion, setClientRandom, setServerRandom,
	getClientRandom, getServerRandom, getCipherSuite,
	cacheCipherSuite, flushCipherSuite,

	encryptRSA, generateKeys, finishedHash, clientVerifySign,

	updateSequenceNumberSmart,

	TlsServer, runOpen, tPut, tGetByte, tGetLine, tGet, tGetContent, tClose,

	debugPrintKeys,

	getRandomGen, setRandomGen,
	SecretKey(..),
) where

import Prelude hiding (read)

import Control.Applicative
import qualified Data.ByteString as BS

import TlsIo
import Basic
	
readFragment :: TlsIo cnt Fragment
readFragment = do
	(ct, v, ebody) <- (,,) <$> readContentType <*> readVersion <*> readLen 2
	body <- decryptBody ct v ebody
	return $ Fragment ct v body

decryptBody :: ContentType -> Version -> BS.ByteString -> TlsIo cnt BS.ByteString
decryptBody = decryptMessage Server

writeFragment :: Fragment -> TlsIo cnt ()
writeFragment (Fragment ct v bs) = do
	cs <- isCiphered Client
	if cs then do
		eb <- encryptBody ct v bs
		writeContentType ct >> writeVersion v >> writeLen 2 eb
	else writeContentType ct >> writeVersion v >> writeLen 2 bs

encryptBody :: ContentType -> Version -> BS.ByteString -> TlsIo cnt BS.ByteString
encryptBody ct v body = do
	ret <- encryptMessage Client ct v body
	updateSequenceNumber Client
	return ret

fragmentUpdateHash :: Fragment -> TlsIo cnt ()
fragmentUpdateHash (Fragment ContentTypeHandshake _ b) = updateHash b
fragmentUpdateHash _ = return ()
