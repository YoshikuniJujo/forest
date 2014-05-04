module Fragment (
	Fragment(..), RawFragment(..), ContentType(..), Version,
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
import Control.Monad
-- import Data.ByteString (ByteString)
-- import qualified Data.ByteString as BS

import TlsIO

readFragment :: Partner -> TlsIO Fragment
readFragment p = do
	RawFragment ct v cbody <- readRawFragment p
	bm <- clientWriteDecrypt cbody
	(body, mac) <- takeBodyMac bm
	liftIO . putStrLn $ "MAC : " ++ show mac
	cmac <- calcMac p ct v body
	liftIO . putStrLn . ("CMAC: " ++) $ show cmac
	case ct of
		ContentTypeHandshake -> updateHash body
		_ -> return ()
	when (mac /= cmac) $ throwError "readFragment: Bad MAC value"
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
