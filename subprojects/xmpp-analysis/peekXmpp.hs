{-# LANGUAGE OverloadedStrings #-}

import Prelude hiding (drop, filter)

import System.IO
import Control.Concurrent (forkIO)
import Control.Monad.IO.Class
import Data.Conduit
import Data.Conduit.List
import qualified Data.Conduit.List as Cd
import Data.Conduit.Binary hiding (drop, isolate)
import Data.Conduit.Network
import Data.Streaming.Network
import Data.ByteString (hPut)
import Text.XML.Stream.Parse
import Network

import EventToElement
import XmppTypes
import Data.XML.Types

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.Text as T
import qualified Data.ByteString.Base64 as B64

main :: IO ()
main = do
	runTCPServer (serverSettings 5222 "*") $ \ad -> do
		h <- connectTo "localhost" (PortNumber 54492)
		forkIO $ appSource ad
--			=$= runIO (hPut h)
--			=$= runIO (hPut stdout)
			=$= parseBytes def
			=$= runIO (hPutStr h . addBegin)
--			=$= filter normal
--			=$= runIO print
			=$= eventToElementAll
--			=$= Cd.map id
			=$= Cd.map elementToStanza
			=$= runIO (hPutStr h . doubleMessage . stanzaToElement)
--			=$= runIO (hPutStr h . doubleMessage)
			=$= runIO (putStrLn . ("\n" ++) . show) -- ("\n" ++) . showContent)
			=$= runIO (putStrLn . showElement . stanzaToElement) -- ("\n" ++) . showContent)
			$$ sinkNull
		sourceHandle h
--			=$= runIO (appWrite ad)
--			=$= runIO (hPut stdout . ("DEBUG: " `BS.append`))
			=$= parseBytes def
			=$= runIO (appWrite ad . BSC.pack . addBeginServer)
			=$= eventToElementAll
			=$= Cd.map elementToStanza
			=$= runIO (appWrite ad . BSC.pack . showElement . stanzaToElement)
--			=$= runIO (appWrite ad . BSC.pack . showElement)
			=$= runIO (putStrLn . ("\n" ++) . show) -- ("\n" ++) . showElement)

--			=$= runIO (BSC.hPut stdout)
--			=$= parseBytes def
--			=$= runIO (appWrite ad . BSC.pack . addBegin)
--			=$= filter normal
--			=$= eventToElement
--			=$= runIO (appWrite ad . BSC.pack . showElement)
--			=$= runIO (putStrLn . ("\n" ++) . showElement)
--			=$= runIO print
			$$ sinkNull

beginDoc, stream, streamServer :: String
beginDoc = "<?xml version=\"1.0\"?>"
stream = "<stream:stream to=\"localhost\" xml:lang=\"en\" version=\"1.0\" " ++
	"xmlns=\"jabber:client\" " ++
	"xmlns:stream=\"http://etherx.jabber.org/streams\">"
streamServer = "<stream:stream xmlns='jabber:client' " ++
	"xmlns:stream='http://etherx.jabber.org/stream' " ++ 
	"id='hoge' from='localhost' version='1.0' xml:lang='en'>"

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

addBeginServer :: Event -> String
addBeginServer EventBeginDocument = beginDoc
addBeginServer (EventBeginElement (Name "stream" _ _) _) = streamServer
addBeginServer _ = ""

normal :: Event -> Bool
normal EventBeginDocument = False
normal (EventBeginElement (Name "stream" _ _) _) = False
normal _ = True

doubleMessage :: Element -> String
doubleMessage e@(Element (Name "message" _ _) _ _) =
	showElement e ++ showElement e
doubleMessage e = showElement e

showContent :: Element -> String
showContent e@(Element (Name "response" _ _) _
	(NodeContent (ContentText txt) : _)) = "here: " ++ BSC.unpack
		((\(Right r) -> r) $ B64.decode $ BSC.pack $ T.unpack txt)
showContent e = showElement e

{-
sinkNull :: Monad m => Sink a m ()
sinkNull = do
	mx <- await
	case mx of
		Just _ -> sinkNull
		_ -> return ()
		-}
