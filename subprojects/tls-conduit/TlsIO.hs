{-# LANGUAGE PackageImports #-}

module TlsIO (
	TlsIO, runTlsIO, evalTlsIO, initTlsState, liftIO,
	Partner(..), ServerHandle(..), ClientHandle(..),
	read, write, readLen, writeLen,

	Handle, Word8, ByteString, BS.unpack, BS.pack
) where

import Prelude hiding (read)

import System.IO
import "monads-tf" Control.Monad.Error
import "monads-tf" Control.Monad.State

import Data.Word
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

import Tools

type TlsIO = ErrorT String (StateT TlsState IO)

data TlsState = TlsState {
	tlssServerHandle :: Handle,
	tlssClientHandle :: Handle
 } deriving Show

data ServerHandle = ServerHandle Handle deriving Show
data ClientHandle = ClientHandle Handle deriving Show

initTlsState :: ClientHandle -> ServerHandle -> TlsState
initTlsState (ClientHandle cl) (ServerHandle sv) = TlsState {
	tlssServerHandle = sv,
	tlssClientHandle = cl
 }

data Partner = Server | Client deriving Show

handle :: Partner -> TlsState -> Handle
handle Server = tlssServerHandle
handle Client = tlssClientHandle

runTlsIO :: TlsIO a -> TlsState -> IO (Either String a, TlsState)
runTlsIO io ts = runErrorT io `runStateT` ts

evalTlsIO :: TlsIO a -> ClientHandle -> ServerHandle -> IO a
evalTlsIO io cl sv = do
	ret <- runErrorT io `evalStateT` initTlsState cl sv
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
