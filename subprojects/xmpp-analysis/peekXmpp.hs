{-# LANGUAGE OverloadedStrings #-}

import Prelude hiding (drop, filter)

import System.IO
import Control.Concurrent (forkIO)
import Control.Monad.IO.Class
import Data.Conduit
import Data.Conduit.List
import Data.Conduit.Binary hiding (drop, isolate)
import Data.Conduit.Network
import Data.Streaming.Network
import Data.ByteString (hPut)
import Text.XML.Stream.Parse
import Network

import EventToElement
import Data.XML.Types

main :: IO ()
main = do
	runTCPServer (serverSettings 5222 "*") $ \ad -> do
		h <- connectTo "localhost" (PortNumber 54492)
		forkIO $ appSource ad
--			=$= runIO (hPut h)
--			=$= runIO (hPut stdout)
			=$= parseBytes def
			=$= runIO (hPutStr h . addBegin)
			=$= filter normal
--			=$= runIO print
			=$= eventToElement
			=$= runIO (hPutStr h . showElement)
			=$= runIO (putStrLn . ("\n" ++) . showElement)
			$$ sinkNull
		sourceHandle h =$= runIO (appWrite ad)
			=$= parseBytes def
--			=$= runIO print
			$$ sinkNull

beginDoc, stream :: String
beginDoc = "<?xml version=\"1.0\"?>"
stream = "<stream:stream to=\"localhost\" xml:lang=\"en\" version=\"1.0\" " ++
	"xmlns=\"jabber:client\" " ++
	"xmlns:stream=\"http://etherx.jabber.org/streams\">"

skip :: Monad m => Int -> Conduit a m a
skip n = drop n >> complete

complete :: Monad m => Conduit a m a
complete = do
	mx <- await
	case mx of
		Just x -> do
			yield x
			complete
		_ -> return ()

runIO :: (Monad m, MonadIO m) => (a -> IO ()) -> Conduit a m a
runIO io = do
	mx <- await
	maybe (return ()) (\x -> liftIO (io x) >> yield x) mx
	runIO io

addBegin :: Event -> String
addBegin EventBeginDocument = beginDoc
addBegin (EventBeginElement (Name "stream" _ _) _) = stream
addBegin _ = ""

normal :: Event -> Bool
normal EventBeginDocument = False
normal (EventBeginElement (Name "stream" _ _) _) = False
normal _ = True

{-
sinkNull :: Monad m => Sink a m ()
sinkNull = do
	mx <- await
	case mx of
		Just _ -> sinkNull
		_ -> return ()
		-}
