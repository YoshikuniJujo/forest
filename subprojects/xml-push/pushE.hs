{-# LANGUAGE OverloadedStrings, FlexibleContexts, PackageImports #-}

import Control.Monad
import "monads-tf" Control.Monad.Trans
import Control.Monad.Base
import Control.Concurrent hiding (yield)
import Control.Concurrent.STM
import Data.Maybe
import Data.Pipe
import Data.Pipe.TChan
import Data.Pipe.ByteString
import System.IO
import Text.XML.Pipe
import Network
import Network.TigHTTP.Client
import Network.TigHTTP.Server
import Network.TigHTTP.Types

import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as LBS

main :: IO ()
main = do
	void $ forkIO client
	server

server :: IO ()
server = do
	soc <- listenOn $ PortNumber 8080
	(h, _, _) <- accept soc
	(inc, otc) <- talk h
	runPipe_ $ fromTChan inc =$= (toTChan otc :: Pipe XmlNode () IO ())

talk :: Handle -> IO (TChan XmlNode, TChan XmlNode)
talk h = do
	inc <- atomically newTChan
	otc <- atomically newTChan
	void . forkIO . runPipe_ . forever $ do
		req <- lift $ getRequest h
		lift . print $ requestPath req
		requestBody req
			=$= xmlEvent
			=$= convert fromJust
			=$= xmlNode []
			=$= toTChan inc
		fromTChan otc =$= await >>= maybe (return ()) (\n ->
			lift . putResponse h
				. (response :: LBS.ByteString ->
					Response Pipe Handle)
				$ LBS.fromChunks [xmlString [n]])
	return (inc, otc)

client :: IO ()
client = do
	h <- connectTo "localhost" $ PortNumber 80
	runPipe_ $ fromHandle stdin =$= clientRun h

clientRun :: Handle -> Pipe BSC.ByteString () IO ()
clientRun h = do
	xmlEvent
		=$= convert fromJust
		=$= xmlNode []
		=$= clientLoop h
		=$= convert (xmlString . (: []))
		=$= printP

clientLoop :: Handle -> Pipe XmlNode XmlNode IO ()
clientLoop h = (await >>=) . maybe (return ()) $ \n -> do
	r <- lift . request h $ post "localhost" 80 "/"
				(Nothing, LBS.fromChunks [xmlString [n]])
	return ()
		=$= responseBody r
		=$= xmlEvent
		=$= convert fromJust
		=$= (xmlNode [] >> return ())
	clientLoop h

printP :: MonadBase IO m => Pipe BSC.ByteString a m ()
printP = await >>= maybe (return ())
	(\s -> lift (liftBase $ BSC.putStr s) >> printP)
