{-# LANGUAGE OverloadedStrings #-}

import Network
import System.IO

import Control.Monad.IO.Class
import Control.Monad

import Data.Conduit
import Data.Conduit.List
import Data.Conduit.Binary

import Text.XML.Stream.Parse

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

import Client

main :: IO ()
main = do
	h <- connectTo "localhost" (PortNumber 54492)
	BS.hPut h $ beginDoc +++ stream
	hPutStr h starttls
	replicateM_ 12 . toTagEnd $ hGetChar h
	tls <- openTlsServer [(undefined, undefined)] h
	tPut tls $ beginDoc +++ stream
	ioSource (tGetContent tls)
		=$= parseBytes def
		=$= runIO print
		$$ sinkNull
--	tGetContent tls >>= print
--	sourceHandle h {- =$= parseBytes def -} =$= runIO BSC.putStrLn $$ sinkNull

ioSource :: MonadIO m => IO a -> Source m a
ioSource io = do
	x <- liftIO io
	yield x
	ioSource io

toTagEnd :: IO Char -> IO ()
toTagEnd io = do
	c <- io
	putChar c
	if c == '>' then return () else toTagEnd io

(+++) = BS.append

beginDoc, stream :: BS.ByteString
beginDoc = "<?xml version=\"1.0\"?>"
stream = "<stream:stream to=\"localhost\" xml:lang=\"en\" version=\"1.0\" " +++
	"xmlns=\"jabber:client\" " +++
	"xmlns:stream=\"http://etherx.jabber.org/streams\">"

starttls :: String
starttls = "<starttls xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"/>"

runIO :: (Monad m, MonadIO m) => (a -> IO ()) -> Conduit a m a
runIO io = do
	mx <- await
	maybe (return ()) (\x -> liftIO (io x) >> yield x) mx
	runIO io

