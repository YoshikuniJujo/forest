{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts,
	PackageImports #-}

import Control.Monad
import "monads-tf" Control.Monad.Trans
import Control.Monad.Base
import Control.Monad.Trans.Control
import Control.Concurrent hiding (yield)
import Control.Concurrent.STM
import Data.Maybe
import Data.HandleLike
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

class XmlPusher xp where
	type PusherArg xp
	generate :: (HandleLike h, MonadBaseControl IO (HandleMonad h)
		) => h -> PusherArg xp -> HandleMonad h (xp h)
	readFrom :: HandleLike h => xp h -> Pipe () XmlNode (HandleMonad h) ()
	writeTo :: HandleLike h =>
		xp h -> Pipe (Maybe XmlNode) () (HandleMonad h) ()

main :: IO ()
main = do
	ch <- connectTo "localhost" $ PortNumber 80
	(cinc, cotc) <- clientC ch
	soc <- listenOn $ PortNumber 8080
	(sh, _, _) <- accept soc
	(sinc, sotc) <- talk sh

	void . forkIO . runPipe_ $ fromTChan cinc
		=$= convert (xmlString . (: []))
		=$= printP
	void . forkIO . runPipe_ $ fromHandle stdin
		=$= xmlEvent
		=$= convert fromJust
		=$= xmlNode []
		=$= toTChan cotc
	runPipe_ $ fromTChan sinc =$= (toTChan sotc :: Pipe XmlNode () IO ())

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

clientC :: Handle -> IO (TChan XmlNode, TChan XmlNode)
clientC h = do
	inc <- atomically newTChan
	otc <- atomically newTChan
	void . forkIO . runPipe_ $
		fromTChan otc =$= clientLoop h =$= toTChan inc
	return (inc, otc)

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
