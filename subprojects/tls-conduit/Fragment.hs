module Fragment (
	Fragment(..), RawFragment(..), ContentType(..), Version(..),
	readFragment, writeFragment,
	readRawFragment, writeRawFragment,

	clientId, clientWriteMacKey,

	setClientRandom, setServerRandom,
	cacheCipherSuite, flushCipherSuite,
	generateMasterSecret,

	decryptRSA, clientWriteDecrypt, finishedHash,
	
	masterSecret, expandedMasterSecret,

	debugPrintKeys,

	ClientHandle(..), ServerHandle(..), Partner(..),
	TlsIO, evalTlsIO, liftIO,

	throwError,
) where

import Prelude hiding (read)

import Control.Applicative
-- import Data.ByteString (ByteString)
-- import qualified Data.ByteString as BS

import TlsIO

readFragment :: Partner -> TlsIO Fragment
readFragment p = do
	RawFragment ct v cbody <- readRawFragment p
	bm <- clientWriteDecrypt cbody
	(body, mac) <- takeBodyMac bm
	liftIO $ putStrLn $ "MAC: " ++ show mac
	case ct of
		ContentTypeHandshake -> updateHash body
		_ -> return ()
	return $ Fragment ct v body

writeFragment :: Partner -> Fragment -> TlsIO ()
writeFragment p (Fragment ct v bs) = writeRawFragment p (RawFragment ct v bs)

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

data ContentType
	= ContentTypeChangeCipherSpec
	| ContentTypeHandshake
	| ContentTypeRaw Word8
	deriving Show

readContentType :: Partner -> TlsIO ContentType
readContentType partner = do
	t <- read partner 1
	let [ct] = unpack t
	return $ case ct of
		20 -> ContentTypeChangeCipherSpec
		22 -> ContentTypeHandshake
		_ -> ContentTypeRaw ct

writeContentType :: Partner -> ContentType -> TlsIO ()
writeContentType partner ContentTypeChangeCipherSpec = write partner $ pack [20]
writeContentType partner ContentTypeHandshake = write partner $ pack [22]
writeContentType partner (ContentTypeRaw ct) = write partner $ pack [ct]

data Version
	= Version Word8 Word8
	deriving Show

readVersion :: Partner -> TlsIO Version
readVersion partner = do
	v <- read partner 2
	let [vmjr, vmnr] = unpack v
	return $ Version vmjr vmnr

writeVersion :: Partner -> Version -> TlsIO ()
writeVersion partner (Version vmjr vmnr) = write partner $ pack [vmjr, vmnr]
