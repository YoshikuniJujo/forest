{-# LANGUAGE OverloadedStrings, FlexibleContexts, PackageImports #-}

import Control.Monad
import "monads-tf" Control.Monad.Trans
import Control.Monad.Base
import Control.Concurrent
import Data.Pipe
import Data.Pipe.ByteString
import System.IO
import System.Environment
import Network
import Network.TigHTTP.Client
import Network.TigHTTP.Server
import Network.TigHTTP.Types

import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as LBS

main :: IO ()
main = server

server :: IO ()
server = do
	soc <- listenOn $ PortNumber 80
	forever $ do
		(h, _, _) <- accept soc
		forkIO client
		void . forkIO . forever $ do
			req <- getRequest h
			print $ requestPath req
			runPipe_ $ requestBody req =$= toHandle stdout
			putResponse h
				. (response ::
					LBS.ByteString -> Response Pipe Handle)
				. LBS.fromChunks $ map BSC.pack ["Hello", "World"]

client :: IO ()
client = do
	h <- connectTo "localhost" $ PortNumber 8080
	clientRun h

clientRun :: Handle -> IO ()
clientRun h = do
	ln <- BSC.getLine
	r <- request h $ post "localhost" 8080 "/" (Nothing, LBS.fromChunks [ln])
	runPipe_ $ responseBody r =$= printP
	clientRun h

printP :: MonadBase IO m => Pipe BSC.ByteString () m ()
printP = await >>= maybe (return ())
	(\s -> lift (liftBase $ BSC.putStr s) >> printP)
