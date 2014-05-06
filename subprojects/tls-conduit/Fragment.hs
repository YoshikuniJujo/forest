{-# LANGUAGE OverloadedStrings #-}

module Fragment (
	Fragment(..), RawFragment(..), ContentType(..), Version,
	readFragment, writeFragment,
	readRawFragment, writeRawFragment,

	clientId, clientWriteMacKey,

	setClientRandom, setServerRandom,
	cacheCipherSuite, flushCipherSuite,
	generateMasterSecret,

	decryptRSA, finishedHash,
	
	masterSecret,

	debugPrintKeys,

	ClientHandle(..), ServerHandle(..), Partner(..),
	TlsIO, evalTlsIO, liftIO,

	throwError, opponent, showRandom,
) where

import Prelude hiding (read)

import Control.Applicative
import Control.Monad
import qualified Data.ByteString as BS

import TlsIO

readFragment :: Partner -> TlsIO Fragment
readFragment p = do
	RawFragment ct v ebody <- readRawFragment p
	body <- decryptBody p ct v ebody
	case ct of
		ContentTypeHandshake -> updateHash body
--		ContentTypeRaw 23 ->  liftIO $ print r
		_ -> return ()
	return $ Fragment ct v body

decryptBody :: Partner -> ContentType -> Version -> ByteString -> TlsIO ByteString
decryptBody p ct v ebody = do
	bm <- decrypt p ebody
	(body, mac) <- takeBodyMac p bm
	cmac <- calcMac p ct v body
	when (mac /= cmac) . throwError $
		"decryptBody: Bad MAC value\n\t" ++
		"ebody         : " ++ show ebody ++ "\n\t" ++
		"bm            : " ++ show ebody ++ "\n\t" ++
		"body          : " ++ show body ++ "\n\t" ++
		"given MAC     : " ++ show mac ++ "\n\t" ++
		"caluculate MAC: " ++ show cmac
	return body

encryptBody :: Partner -> ContentType -> Version -> ByteString -> TlsIO ByteString
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

writeFragment :: Partner -> Fragment -> TlsIO ()
writeFragment p (Fragment ct v bs) = do
	cs <- getCipherSuite (opponent p)
	case cs of
		TLS_RSA_WITH_AES_128_CBC_SHA -> do
			eb <- encryptBody (opponent p) ct v bs
			writeRawFragment p (RawFragment ct v eb)
		TLS_NULL_WITH_NULL_NULL -> writeRawFragment p (RawFragment ct v bs)
		_ -> throwError "writeFragment: not implemented"

readRawFragment :: Partner -> TlsIO RawFragment
readRawFragment p =
	RawFragment <$> readContentType p <*> readVersion p <*> readLen p 2

writeRawFragment :: Partner -> RawFragment -> TlsIO ()
writeRawFragment p (RawFragment ct v bs) =
	writeContentType p ct >> writeVersion p v >> writeLen p 2 bs
	
data RawFragment
	= RawFragment ContentType Version ByteString
	deriving Show

data Fragment
	= Fragment ContentType Version ByteString
	deriving Show
