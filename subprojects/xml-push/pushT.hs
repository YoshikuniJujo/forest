{-# LANGUAGE OverloadedStrings, TupleSections, ScopedTypeVariables,
	TypeFamilies, FlexibleContexts, PackageImports #-}

import Prelude hiding (filter)

import Control.Monad
import "monads-tf" Control.Monad.Trans
import Control.Monad.Base
import Control.Monad.Trans.Control
import Control.Concurrent hiding (yield)
import Control.Concurrent.STM
import Data.Maybe
import Data.HandleLike
import Data.Pipe
import Data.Pipe.Flow
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
	type NumOfHandle xp :: * -> *
	generate :: (HandleLike h, MonadBaseControl IO (HandleMonad h)
		) => NumOfHandle xp h -> PusherArg xp -> HandleMonad h (xp h)
	readFrom :: (HandleLike h, MonadBase IO (HandleMonad h)) =>
		xp h -> Pipe () XmlNode (HandleMonad h) ()
	writeTo :: (HandleLike h, MonadBase IO (HandleMonad h)) =>
		xp h -> Pipe (Maybe XmlNode) () (HandleMonad h) ()

data Two h = Two h h deriving Show

data HttpPush h = HttpPush {
	needReply :: TVar Bool,
	clientReadChan :: TChan (XmlNode, Bool),
	clientWriteChan :: TChan (Maybe XmlNode),
	serverReadChan :: TChan (XmlNode, Bool),
	serverWriteChan :: TChan (Maybe XmlNode)
	}

instance XmlPusher HttpPush where
	type PusherArg HttpPush = ()
	type NumOfHandle HttpPush = Two
	generate (Two ch sh) () = mkHttpPush ch sh
	readFrom hp = fromTChans [clientReadChan hp, serverReadChan hp] =$=
		setNeedReply (needReply hp)
	writeTo hp = (convert (() ,) =$=) . toTChansM $ do
		nr <- liftBase . atomically . readTVar $ needReply hp
		liftBase . atomically $ writeTVar (needReply hp) False
		liftBase $ print nr
		return [
			(const nr, serverWriteChan hp),
			(const True, clientWriteChan hp) ]

setNeedReply :: MonadBase IO m => TVar Bool -> Pipe (a, Bool) a m ()
setNeedReply nr = await >>= maybe (return ()) (\(x, b) ->
	lift (liftBase . atomically $ writeTVar nr b) >> yield x >> setNeedReply nr)

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
	soc <- listenOn $ PortNumber 80
	(sh, _, _) <- accept soc
	ch <- connectTo "localhost" $ PortNumber 8080
	(hp :: HttpPush Handle) <- generate (Two ch sh) ()
	void . forkIO . runPipe_ $ readFrom hp
		=$= convert (xmlString . (: []))
		=$= toHandle stdout
	runPipe_ $ fromHandle stdin
		=$= xmlEvent
		=$= convert fromJust
		=$= xmlNode []
		=$= convert Just
		=$= writeTo hp

talk :: (HandleLike h, MonadBaseControl IO (HandleMonad h)
	) => h -> HandleMonad h (TChan (XmlNode, Bool), TChan (Maybe XmlNode))
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
			=$= convert (, True)
			=$= toTChan inc
		fromTChan otc =$= await >>= maybe (return ()) (\mn ->
			lift . putResponse h . responseP $ case mn of
				Just n -> LBS.fromChunks [xmlString [n]]
				_ -> "")
	return (inc, otc)

responseP :: HandleLike h => LBS.ByteString -> Response Pipe h
responseP = response

clientC :: (HandleLike h, MonadBaseControl IO (HandleMonad h)
	) => h -> HandleMonad h (TChan (XmlNode, Bool), TChan (Maybe XmlNode))
clientC h = do
	inc <- liftBase $ atomically newTChan
	otc <- liftBase $ atomically newTChan
	void . liftBaseDiscard forkIO . runPipe_ $ fromTChan otc
		=$= filter isJust
		=$= convert fromJust
		=$= clientLoop h
		=$= convert (, False)
		=$= toTChan inc
	return (inc, otc)

clientLoop :: (HandleLike h, MonadBaseControl IO (HandleMonad h)
	) => h -> Pipe XmlNode XmlNode (HandleMonad h) ()
clientLoop h = (await >>=) . maybe (return ()) $ \n -> do
	r <- lift . request h $ post "localhost" 8080 "/"
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
