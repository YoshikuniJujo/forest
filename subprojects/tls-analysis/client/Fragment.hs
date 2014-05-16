{-# LANGUAGE OverloadedStrings #-}

module Fragment (
	readFragment, writeFragment, fragmentUpdateHash,

	TlsIo, evalTlsIo, liftIO, throwError, readCached, randomByteString,
	Partner(..),

	setVersion, setClientRandom, setServerRandom,
	cacheCipherSuite, flushCipherSuite,

	encryptRSA, generateKeys, finishedHash, clientVerifySign,

	updateSequenceNumberSmart,
) where

import Prelude hiding (read)

import Control.Applicative
import Control.Monad
import qualified Data.ByteString as BS

import TlsIo
import Basic
	
readFragment :: TlsIo cnt Fragment
readFragment = do
	(ct, v, ebody) <- (,,) <$> readContentType <*> readVersion <*> readLen 2
	body <- decryptBody ct v ebody
	return $ Fragment ct v body

decryptBody :: ContentType -> Version -> BS.ByteString -> TlsIo cnt BS.ByteString
decryptBody ct v ebody = do
	bm <- decrypt Server ebody
	(body, mac) <- bodyMac Server bm
	cmac <- calcMac Server ct v body
	when (mac /= cmac) . throwError $
		"decryptBody: Bad MAC value\n\t" ++
		"ebody         : " ++ show ebody ++ "\n\t" ++
		"bm            : " ++ show bm ++ "\n\t" ++
		"body          : " ++ show body ++ "\n\t" ++
		"given MAC     : " ++ show mac ++ "\n\t" ++
		"caluculate MAC: " ++ show cmac
	return body

writeFragment :: Fragment -> TlsIo cnt ()
writeFragment (Fragment ct v bs) = do
	cs <- isCiphered Client
	case cs of
		True -> do
			eb <- encryptBody ct v bs
			writeContentType ct >> writeVersion v >> writeLen 2 eb
		False -> writeContentType ct >> writeVersion v >> writeLen 2 bs

encryptBody :: ContentType -> Version -> BS.ByteString -> TlsIo cnt BS.ByteString
encryptBody ct v body = do
	mac <- calcMac Client ct v body
	updateSequenceNumber Client
	let	bm = body `BS.append` mac
		plen = 16 - (BS.length bm + 1) `mod` 16
		padd = BS.replicate (plen + 1) $ fromIntegral plen
	encrypt Client (bm `BS.append` padd)

fragmentUpdateHash :: Fragment -> TlsIo cnt ()
fragmentUpdateHash (Fragment ContentTypeHandshake _ b) = updateHash b
fragmentUpdateHash _ = return ()
