{-# LANGUAGE OverloadedStrings #-}

module Fragment (
	Fragment(..), RawFragment(..), ContentType(..), Version,
	readFragment, readFragmentNoHash, fragmentUpdateHash, writeFragment,

	setVersion, setClientRandom, setServerRandom,
	cacheCipherSuite, flushCipherSuite,
	generateMasterSecret,

	finishedHash,
	encryptRSA,

	Partner(..),
	TlsIo, evalTlsIo, liftIO, throwError,

	updateSequenceNumberSmart,
	randomByteString,
	readCached,
	clientVerifySign,
) where

import Prelude hiding (read)

import Control.Applicative
import Control.Monad
import qualified Data.ByteString as BS

import TlsIo
import Basic

readFragment :: TlsIo cnt Fragment
readFragment = do
	RawFragment ct v ebody <- readRawFragment
	body <- decryptBody Server ct v ebody
	case ct of
		ContentTypeHandshake -> updateHash body
		_ -> return ()
	return $ Fragment ct v body

readFragmentNoHash :: TlsIo cnt Fragment
readFragmentNoHash = do
	RawFragment ct v ebody <- readRawFragment
	body <- decryptBody Server ct v ebody
	return $ Fragment ct v body

fragmentUpdateHash :: Fragment -> TlsIo cnt ()
fragmentUpdateHash (Fragment ContentTypeHandshake _ b) = updateHash b
fragmentUpdateHash _ = return ()

decryptBody :: Partner ->
	ContentType -> Version -> BS.ByteString -> TlsIo cnt BS.ByteString
decryptBody p ct v ebody = do
	bm <- decrypt p ebody
	(body, mac) <- takeBodyMac p bm
	cmac <- calcMac p ct v body
	when (mac /= cmac) . throwError $
		"decryptBody: Bad MAC value\n\t" ++
		"ebody         : " ++ show ebody ++ "\n\t" ++
		"bm            : " ++ show bm ++ "\n\t" ++
		"body          : " ++ show body ++ "\n\t" ++
		"given MAC     : " ++ show mac ++ "\n\t" ++
		"caluculate MAC: " ++ show cmac
	return body

encryptBody :: Partner ->
	ContentType -> Version -> BS.ByteString -> TlsIo cnt BS.ByteString
encryptBody p ct v body = do
	mac <- calcMac p ct v body
	_ <- updateSequenceNumber p
	let	bm = body `BS.append` mac
		padd = mkPadd 16 $ BS.length bm
	encrypt p (bm `BS.append` padd)

mkPadd :: Int -> Int -> BS.ByteString
mkPadd bs len = let
	plen = bs - ((len + 1) `mod` bs) in
	BS.replicate (plen + 1) $ fromIntegral plen

writeFragment :: Fragment -> TlsIo cnt ()
writeFragment (Fragment ct v bs) = do
	cs <- getCipherSuite Client
	case cs of
		TLS_RSA_WITH_AES_128_CBC_SHA -> do
			eb <- encryptBody Client ct v bs
			writeRawFragment (RawFragment ct v eb)
		TLS_NULL_WITH_NULL_NULL -> writeRawFragment (RawFragment ct v bs)
		_ -> throwError "writeFragment: not implemented"

readRawFragment :: TlsIo cnt RawFragment
readRawFragment =
	RawFragment <$> readContentType <*> readVersion <*> readLen 2

writeRawFragment :: RawFragment -> TlsIo cnt ()
writeRawFragment (RawFragment ct v bs) =
	writeContentType ct >> writeVersion v >> writeLen 2 bs
	
data RawFragment
	= RawFragment ContentType Version BS.ByteString
	deriving Show
