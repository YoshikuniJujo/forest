{-# LANGUAGE TypeFamilies, FlexibleContexts,
	PackageImports #-}

module HttpPullCl (
	HttpPullCl, HttpPullClArgs(..), One(..), testPusher,
	) where

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
import Text.XML.Pipe
import Network.TigHTTP.Client
import Network.TigHTTP.Types

import qualified Data.ByteString.Lazy as LBS

import XmlPusher

data HttpPullCl pt h = HttpPullCl
	(Pipe () XmlNode (HandleMonad h) ())
	(Pipe XmlNode () (HandleMonad h) ())

data HttpPullClArgs = HttpPullClArgs {
	domainName :: String,
	path :: FilePath,
	poll :: XmlNode,
	isPending :: XmlNode -> Bool,
	duration :: XmlNode -> Maybe Int
	}

instance XmlPusher (HttpPullCl pt) where
	type NumOfHandle (HttpPullCl pt) = One
	type PusherArg (HttpPullCl pt) = HttpPullClArgs
	type PushedType (HttpPullCl pt) = pt
	generate = makeHttpPull
	readFrom (HttpPullCl r _) = r
	writeTo (HttpPullCl _ w) = filter isJust
		=$= convert (fst . fromJust)
		=$= w

makeHttpPull :: (HandleLike h, MonadBaseControl IO (HandleMonad h)) =>
	One h -> HttpPullClArgs -> HandleMonad h (HttpPullCl pt h)
makeHttpPull (One h) (HttpPullClArgs hn fp pl ip gdr) = do
	dr <- liftBase . atomically $ newTVar Nothing
	(inc, otc) <- talkC h hn fp pl ip dr gdr
	return $ HttpPullCl (fromTChan inc) (toTChan otc)

talkC :: (HandleLike h, MonadBaseControl IO (HandleMonad h)) =>
	h -> String -> FilePath -> XmlNode -> (XmlNode -> Bool) ->
	TVar (Maybe Int) -> (XmlNode -> Maybe Int) ->
	HandleMonad h (TChan XmlNode, TChan XmlNode)
talkC h addr pth pl ip dr gdr = do
	inc <- liftBase $ atomically newTChan
	inc' <- liftBase $ atomically newTChan
	otc <- liftBase $ atomically newTChan
	void . liftBaseDiscard forkIO . runPipe_ $ fromTChan otc
		=$= talk h addr pth
		=$= setDuration dr gdr
		=$= toTChan inc
	void . liftBaseDiscard forkIO . forever $ do
		d <- liftBase . atomically $ do
			md <- readTVar dr
			case md of
				Just d -> return d
				_ -> retry
		liftBase $ threadDelay d -- 10000000
		liftBase $ polling pl ip inc inc' otc
	return (inc', otc)

setDuration dr gdr = (await >>=) . maybe (return ()) $ \n -> case gdr n of
	Just d -> do
		lift . liftBase . atomically $ writeTVar dr (Just d)
		yield n >> setDuration dr gdr
	_ -> yield n >> setDuration dr gdr

polling :: XmlNode -> (XmlNode -> Bool) ->
	TChan XmlNode -> TChan XmlNode -> TChan XmlNode -> IO ()
polling pl ip i i' o = do
	atomically $ writeTChan o pl
	r <- atomically $ readTChan i
	if ip r
	then atomically (writeTChan i' r) >> polling pl ip i i' o
	else return ()

talk :: (HandleLike h) =>
	h -> String -> FilePath -> Pipe XmlNode XmlNode (HandleMonad h) ()
talk h addr pth = (await >>=) . (maybe (return ())) $ \n -> do
	let m = LBS.fromChunks [xmlString [n]]
	r <- lift . request h $ post addr 80 pth (Nothing, m)
	void $ return ()
		=$= responseBody r
		=$= xmlEvent
		=$= convert fromJust
		=$= xmlNode []
	talk h addr pth
