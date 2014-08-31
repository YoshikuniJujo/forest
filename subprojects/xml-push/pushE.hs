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
		) => h -> h -> PusherArg xp -> HandleMonad h (xp h)
	readFrom :: HandleLike h => xp h -> Pipe () XmlNode (HandleMonad h) ()
	writeTo :: HandleLike h =>
		xp h -> Pipe (Maybe XmlNode) () (HandleMonad h) ()

data HttpPush h = HttpPush {
	needReply :: TVar Bool,
	clientReadChan :: TChan XmlNode,
	clientWriteChan :: TChan XmlNode,
	serverReadChan :: TChan XmlNode,
	serverWriteChan :: TChan XmlNode
	}

instance XmlPusher HttpPush where
	type PusherArg HttpPush = ()
	generate ch sh () = mkHttpPush ch sh

mkHttpPush :: (
	HandleLike h, MonadBaseControl IO (HandleMonad h)
	) => h -> h -> HandleMonad h (HttpPush h)
mkHttpPush ch sh = do
	v <- liftBase . atomically $ newTVar False
	(ci, co) <- clientC ch
	(si, so) <- talk sh
	return $ HttpPush v ci co si so

main :: IO ()
main = do
	ch <- connectTo "localhost" $ PortNumber 80
	soc <- listenOn $ PortNumber 8080
	(sh, _, _) <- accept soc
	HttpPush _ cinc cotc sinc sotc <- generate ch sh ()
	void . forkIO . runPipe_ $ fromTChan cinc
		=$= convert (xmlString . (: []))
		=$= printP
	void . forkIO . runPipe_ $ fromHandle stdin
		=$= xmlEvent
		=$= convert fromJust
		=$= xmlNode []
		=$= toTChan cotc
	runPipe_ $ fromTChan sinc =$= (toTChan sotc :: Pipe XmlNode () IO ())

talk :: (HandleLike h, MonadBaseControl IO (HandleMonad h)
	) => h -> HandleMonad h (TChan XmlNode, TChan XmlNode)
talk h = do
	inc <- liftBase $ atomically newTChan
	otc <- liftBase $ atomically newTChan
	void . liftBaseDiscard forkIO . runPipe_ . forever $ do
		req <- lift $ getRequest h
		lift . liftBase . print $ requestPath req
		requestBody req
			=$= xmlEvent
			=$= convert fromJust
			=$= xmlNode []
			=$= toTChan inc
		fromTChan otc =$= await >>= maybe (return ()) (\n ->
			lift . putResponse h . responseP
				$ LBS.fromChunks [xmlString [n]])
	return (inc, otc)

responseP :: HandleLike h => LBS.ByteString -> Response Pipe h
responseP = response

clientC :: (HandleLike h, MonadBaseControl IO (HandleMonad h)
	) => h -> HandleMonad h (TChan XmlNode, TChan XmlNode)
clientC h = do
	inc <- liftBase $ atomically newTChan
	otc <- liftBase $ atomically newTChan
	void . liftBaseDiscard forkIO . runPipe_ $
		fromTChan otc =$= clientLoop h =$= toTChan inc
	return (inc, otc)

clientLoop :: (HandleLike h, MonadBaseControl IO (HandleMonad h)
	) => h -> Pipe XmlNode XmlNode (HandleMonad h) ()
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
