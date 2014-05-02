{-# LANGUAGE PackageImports #-}

module TlsIO (
	TlsIO, runTlsIO, evalTlsIO, initTlsState, liftIO,
	Partner(..), ServerHandle(..), ClientHandle(..),
	read, write, readLen, writeLen,
	decryptRSA,

	Handle, Word8, ByteString, BS.unpack, BS.pack
) where

import Prelude hiding (read)

import System.IO
import "monads-tf" Control.Monad.Error
import "monads-tf" Control.Monad.State

import Data.Word
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

import Crypto.PubKey.RSA
import Crypto.PubKey.RSA.PKCS15

import Tools

type TlsIO = ErrorT String (StateT TlsState IO)

data TlsState = TlsState {
	tlssServerHandle :: Handle,
	tlssClientHandle :: Handle,
	privateKey :: PrivateKey
 } deriving Show

data ServerHandle = ServerHandle Handle deriving Show
data ClientHandle = ClientHandle Handle deriving Show

initTlsState :: ClientHandle -> ServerHandle -> PrivateKey -> TlsState
initTlsState (ClientHandle cl) (ServerHandle sv) pk = TlsState {
	tlssServerHandle = sv,
	tlssClientHandle = cl,
	privateKey = pk
 }

data Partner = Server | Client deriving Show

handle :: Partner -> TlsState -> Handle
handle Server = tlssServerHandle
handle Client = tlssClientHandle

runTlsIO :: TlsIO a -> TlsState -> IO (Either String a, TlsState)
runTlsIO io ts = runErrorT io `runStateT` ts

evalTlsIO :: TlsIO a -> ClientHandle -> ServerHandle -> PrivateKey -> IO a
evalTlsIO io cl sv pk = do
	ret <- runErrorT io `evalStateT` initTlsState cl sv pk
	case ret of
		Right r -> return r
		Left err -> error err

read :: Partner -> Int -> TlsIO ByteString
read partner n = do
	h <- gets $ handle partner
	r <- liftIO $ BS.hGet h n
	if BS.length r == n
		then return r
		else throwError $ "Basic.read: bad reading: " ++
			show (BS.length r) ++ " " ++ show n

write :: Partner -> ByteString -> TlsIO ()
write partner dat = do
	h <- gets $ handle partner
	liftIO $ BS.hPut h dat

readLen :: Partner -> Int -> TlsIO ByteString
readLen partner n = do
	len <- read partner n
	read partner $ byteStringToInt len

writeLen :: Partner -> Int -> ByteString -> TlsIO ()
writeLen partner n bs = do
	write partner $ intToByteString n $ BS.length bs
	write partner bs

decryptRSA :: ByteString -> TlsIO ByteString
decryptRSA e = do
	pk <- gets privateKey
	case decrypt Nothing pk e of
		Right d -> return d
		Left err -> throwError $ show err
