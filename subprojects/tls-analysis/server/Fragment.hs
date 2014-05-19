{-# LANGUAGE OverloadedStrings #-}

module Fragment (
	Fragment(..), RawFragment(..), ContentType(..), Version,
	readFragment, readFragmentNoHash, fragmentUpdateHash, writeFragment,
	readRawFragment, writeRawFragment,

	clientWriteMacKey,

	setClientRandom, setServerRandom, setVersion,
	cacheCipherSuite, flushCipherSuite,
	generateMasterSecret,

	decryptRSA, finishedHash,
	encryptRSA,
	
	masterSecret,

--	debugPrintKeys,
	debugShowKeys,

	ClientHandle(..),
	Partner(..),
	TlsIo, evalTlsIo, liftIO,

	throwError, showRandom,
	updateSequenceNumberSmart,
	randomByteString,
	readCached,
	clientVerifyHash,
) where

import Prelude hiding (read)

import Control.Applicative
import Control.Monad
import qualified Data.ByteString as BS

import TlsIo
import Basic

readFragment :: Partner -> TlsIo cnt Fragment
readFragment p = do
	RawFragment ct v ebody <- readRawFragment
	body <- decryptBody p ct v ebody
	case ct of
		ContentTypeHandshake -> updateHash body
--		ContentTypeRaw 23 ->  liftIO $ print r
		_ -> return ()
	case p of
		Client -> return () -- updateSequenceNumberSmart Client
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

decryptBody :: Partner -> ContentType -> Version -> ByteString -> TlsIo cnt ByteString
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

encryptBody :: Partner -> ContentType -> Version -> ByteString -> TlsIo cnt ByteString
encryptBody p ct v body = do
	mac <- calcMac p ct v body
	_ <- updateSequenceNumber p
	let	bm = body `BS.append` mac
		padd = mkPadd 16 $ BS.length bm
	encrypt p (bm `BS.append` padd)

mkPadd :: Int -> Int -> ByteString
mkPadd bs len = let
	plen = bs - ((len + 1) `mod` bs) in
	BS.replicate (plen + 1) $ fromIntegral plen

writeFragment :: Fragment -> TlsIo cnt ()
writeFragment (Fragment ct v bs) = do
	cs <- getCipherSuite Server
	case cs of
		TLS_RSA_WITH_AES_128_CBC_SHA -> do
			eb <- encryptBody Server ct v bs
			writeRawFragment (RawFragment ct v eb)
		TLS_NULL_WITH_NULL_NULL -> writeRawFragment (RawFragment ct v bs)
		_ -> throwError "writeFragment: not implemented"

readRawFragment :: TlsIo cnt RawFragment
readRawFragment = RawFragment <$> readContentType <*> readVersion <*> readLen 2

writeRawFragment :: RawFragment -> TlsIo cnt ()
writeRawFragment (RawFragment ct v bs) =
	writeContentType ct >> writeVersion v >> writeLen 2 bs
	
data RawFragment
	= RawFragment ContentType Version ByteString
	deriving Show
