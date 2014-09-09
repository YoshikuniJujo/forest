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
import Data.Pipe.TChan
import System.IO
import Text.XML.Pipe
import Network.TigHTTP.Client
import Network.TigHTTP.Types

import qualified Data.ByteString.Lazy as LBS

import XmlPusher

data HttpPullCl h = HttpPullCl
	(Pipe () XmlNode (HandleMonad h) ())
	(Pipe XmlNode () (HandleMonad h) ())

data HttpPullClArgs = HttpPullClArgs {
	domainName :: String,
	portNumber :: Int,
	path :: FilePath,
	poll :: XmlNode,
	isPending :: XmlNode -> Bool,
	duration :: XmlNode -> Maybe Int,
	getPath :: XmlNode -> FilePath
	}

instance XmlPusher HttpPullCl where
	type NumOfHandle HttpPullCl = One
	type PusherArg HttpPullCl = HttpPullClArgs
	type PushedType HttpPullCl = ()
	generate = makeHttpPull
	readFrom (HttpPullCl r _) = r
	writeTo (HttpPullCl _ w) = convert fst =$= w

makeHttpPull :: (HandleLike h, MonadBaseControl IO (HandleMonad h)) =>
	One h -> HttpPullClArgs -> HandleMonad h (HttpPullCl h)
makeHttpPull (One h) (HttpPullClArgs hn pn fp pl ip gdr gp) = do
	dr <- liftBase . atomically $ newTVar Nothing
	(inc, otc) <- talkC h hn pn fp gp pl ip dr gdr
	return $ HttpPullCl (fromTChan inc) (toTChan otc)

talkC :: (HandleLike h, MonadBaseControl IO (HandleMonad h)) =>
	h -> String -> Int -> FilePath -> (XmlNode -> FilePath) ->
	XmlNode -> (XmlNode -> Bool) ->
	TVar (Maybe Int) -> (XmlNode -> Maybe Int) ->
	HandleMonad h (TChan XmlNode, TChan XmlNode)
talkC h addr pn pth gp pl ip dr gdr = do
	lock <- liftBase $ atomically newTChan
	liftBase . atomically $ writeTChan lock ()
	inc <- liftBase $ atomically newTChan
	inc' <- liftBase $ atomically newTChan
	otc <- liftBase $ atomically newTChan
	otc' <- liftBase $ atomically newTChan
	void . liftBaseDiscard forkIO . runPipe_ $ fromTChan otc
		=$= conversation lock h addr pn pth gp dr gdr
		=$= toTChan inc
	void . liftBaseDiscard forkIO . runPipe_ $ fromTChan otc'
		=$= conversation lock h addr pn pth gp dr gdr
		=$= toTChan inc'
	void . liftBaseDiscard forkIO . forever $ do
		d <- liftBase . atomically $ do
			md <- readTVar dr
			case md of
				Just d -> return d
				_ -> retry
		liftBase $ threadDelay d
		liftBase $ polling pl ip inc' inc otc'
	return (inc, otc)

conversation :: (HandleLike h, MonadBase IO (HandleMonad h)) =>
	TChan () -> h -> String -> Int ->
	FilePath -> (XmlNode -> FilePath) ->
	TVar (Maybe a) -> (XmlNode -> Maybe a) ->
	Pipe XmlNode XmlNode (HandleMonad h) ()
conversation lock h addr pn pth gp dr gdr =
	talk lock h addr pn pth gp =$= setDuration dr gdr

setDuration :: MonadBase IO m => TVar (Maybe a) -> (o -> Maybe a) -> Pipe o o m ()
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
	hFlush stdout
	if ip r
	then atomically (writeTChan i' r) >> polling pl ip i i' o
	else return ()

talk :: (MonadBase IO (HandleMonad h), HandleLike h) =>
	TChan () -> h -> String -> Int ->
	FilePath -> (XmlNode -> FilePath) ->
	Pipe XmlNode XmlNode (HandleMonad h) ()
talk lock h addr pn pth gp = (await >>=) . (maybe (return ())) $ \n -> do
	let m = LBS.fromChunks [xmlString [n]]
	lift . liftBase . atomically $ readTChan lock
	r <- lift . request h $ post addr pn (pth ++ "/" ++ gp n) (Nothing, m)
	void $ return ()
		=$= responseBody r
		=$= xmlEvent
		=$= convert fromJust
		=$= xmlNode []
	lift . liftBase . atomically $ writeTChan lock ()
	talk lock h addr pn pth gp
