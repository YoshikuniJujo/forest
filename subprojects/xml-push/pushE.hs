{-# LANGUAGE OverloadedStrings, FlexibleContexts, PackageImports #-}

import Control.Monad
import "monads-tf" Control.Monad.Trans
import Control.Monad.Base
import Control.Concurrent hiding (yield)
import Data.Maybe
import Data.Pipe
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
	void . forever $ do
		req <- getRequest h
		print $ requestPath req
		runPipe_ $ requestBody req
			=$= xmlEvent
			=$= convert fromJust
			=$= xmlNode []
			=$= convert (xmlString . (: []))
			=$= toHandle stdout
		runPipe_ $ yield "<HELLO>WORLD</HELLO>"
			=$= xmlEvent
			=$= convert fromJust
			=$= xmlNode []
			=$= await >>= maybe (return ()) (\n ->
				lift . putResponse h
					. (response :: LBS.ByteString ->
						Response Pipe Handle)
					$ LBS.fromChunks [xmlString [n]])

client :: IO ()
client = do
	h <- connectTo "localhost" $ PortNumber 80
	clientRun h

clientRun :: Handle -> IO ()
clientRun h = do
	ln <- BSC.getLine
	r <- request h $ post "localhost" 80 "/" (Nothing, LBS.fromChunks [ln])
	runPipe_ $ responseBody r =$= printP
	clientRun h

printP :: MonadBase IO m => Pipe BSC.ByteString () m ()
printP = await >>= maybe (return ())
	(\s -> lift (liftBase $ BSC.putStr s) >> printP)
