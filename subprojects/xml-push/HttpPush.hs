{-# LANGUAGE OverloadedStrings, TupleSections, TypeFamilies, FlexibleContexts,
	PackageImports #-}

module HttpPush (
	HttpPush, HttpPushArgs(..), Two(..), testPusher,
	) where

import Prelude hiding (filter)

import Control.Applicative
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
import Text.XML.Pipe
import Network.TigHTTP.Client
import Network.TigHTTP.Server
import Network.TigHTTP.Types

import qualified Data.ByteString.Lazy as LBS

import XmlPusher

data HttpPush h = HttpPush {
	needReply :: TVar Bool,
	clientReadChan :: TChan (XmlNode, Bool),
	clientWriteChan :: TChan (Maybe XmlNode),
	serverReadChan :: TChan (XmlNode, Bool),
	serverWriteChan :: TChan (Maybe XmlNode) }

data HttpPushArgs = HttpPushArgs {
	domainName :: String,
	portNumber :: Int,
	path :: FilePath,
	getPath :: XmlNode -> FilePath,
	wantResponse :: XmlNode -> Bool
	}

instance XmlPusher HttpPush where
	type NumOfHandle HttpPush = Two
	type PusherArg HttpPush = HttpPushArgs
	type PushedType HttpPush = Bool
	generate (Two ch sh) = makeHttpPush ch sh
	readFrom hp = fromTChans [clientReadChan hp, serverReadChan hp] =$=
		setNeedReply (needReply hp)
	writeTo hp = (convert (((), ) . (fst <$>)) =$=) . toTChansM $ do
		nr <- liftBase . atomically . readTVar $ needReply hp
		liftBase . atomically $ writeTVar (needReply hp) False
		return [
			(const nr, serverWriteChan hp),
			(const True, clientWriteChan hp) ]

setNeedReply :: MonadBase IO m => TVar Bool -> Pipe (a, Bool) a m ()
setNeedReply nr = await >>= maybe (return ()) (\(x, b) ->
	lift (liftBase . atomically $ writeTVar nr b) >> yield x >> setNeedReply nr)

makeHttpPush :: (HandleLike h, MonadBaseControl IO (HandleMonad h)) =>
	h -> h -> HttpPushArgs -> HandleMonad h (HttpPush h)
makeHttpPush ch sh (HttpPushArgs hn pn pt gp wr) = do
	v <- liftBase . atomically $ newTVar False
	(ci, co) <- clientC ch hn pn pt gp
	(si, so) <- talk wr sh
	return $ HttpPush v ci co si so

clientC :: (HandleLike h, MonadBaseControl IO (HandleMonad h)) =>
	h -> String -> Int -> FilePath -> (XmlNode -> FilePath) ->
	HandleMonad h (TChan (XmlNode, Bool), TChan (Maybe XmlNode))
clientC h hn pn pt gp = do
	inc <- liftBase $ atomically newTChan
	otc <- liftBase $ atomically newTChan
	void . liftBaseDiscard forkIO . runPipe_ $ fromTChan otc
		=$= filter isJust
		=$= convert fromJust
		=$= clientLoop h hn pn pt gp
		=$= convert (, False)
		=$= toTChan inc
	return (inc, otc)

clientLoop :: (HandleLike h, MonadBaseControl IO (HandleMonad h)) =>
	h -> String -> Int -> FilePath -> (XmlNode -> FilePath) ->
	Pipe XmlNode XmlNode (HandleMonad h) ()
clientLoop h hn pn pt gp = (await >>=) . maybe (return ()) $ \n -> do
	r <- lift . request h $ post hn pn (pt ++ "/" ++ gp n)
		(Nothing, LBS.fromChunks [xmlString [n]])
	return ()
		=$= responseBody r
		=$= xmlEvent
		=$= convert fromJust
		=$= (xmlNode [] >> return ())
	clientLoop h hn pn pt gp

talk :: (HandleLike h, MonadBaseControl IO (HandleMonad h)) =>
	(XmlNode -> Bool) ->
	h -> HandleMonad h (TChan (XmlNode, Bool), TChan (Maybe XmlNode))
talk wr h = do
	inc <- liftBase $ atomically newTChan
	otc <- liftBase $ atomically newTChan
	void . liftBaseDiscard forkIO . runPipe_ . forever $ do
		req <- lift $ getRequest h
		requestBody req
			=$= xmlEvent
			=$= convert fromJust
			=$= xmlNode []
			=$= checkReply wr otc
			=$= toTChan inc
		fromTChan otc =$= await >>= maybe (return ()) (\mn ->
			lift . putResponse h . responseP $ case mn of
				Just n -> LBS.fromChunks [xmlString [n]]
				_ -> "")
	return (inc, otc)

checkReply :: MonadBase IO m => (XmlNode -> Bool) -> TChan (Maybe XmlNode) ->
	Pipe XmlNode (XmlNode, Bool) m ()
checkReply wr o = (await >>=) . maybe (return ()) $ \n ->
	if wr n
	then yield (n, True) >> checkReply wr o
	else do	lift (liftBase . atomically $ writeTChan o Nothing)
		yield (n, False)
		checkReply wr o

responseP :: HandleLike h => LBS.ByteString -> Response Pipe h
responseP = response
