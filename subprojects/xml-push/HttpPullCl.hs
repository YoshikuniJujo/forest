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
import System.IO
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
	duration :: XmlNode -> Maybe Int,
	getPath :: XmlNode -> FilePath
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
makeHttpPull (One h) (HttpPullClArgs hn fp pl ip gdr gp) = do
	dr <- liftBase . atomically $ newTVar Nothing
	(inc, otc) <- talkC h hn fp gp pl ip dr gdr
	return $ HttpPullCl (fromTChan inc) (toTChan otc)

talkC :: (HandleLike h, MonadBaseControl IO (HandleMonad h)) =>
	h -> String -> FilePath -> (XmlNode -> FilePath) -> XmlNode -> (XmlNode -> Bool) ->
	TVar (Maybe Int) -> (XmlNode -> Maybe Int) ->
	HandleMonad h (TChan XmlNode, TChan XmlNode)
talkC h addr pth gp pl ip dr gdr = do
	lock <- liftBase $ atomically newTChan
	liftBase . atomically $ writeTChan lock ()
	inc <- liftBase $ atomically newTChan
	inc' <- liftBase $ atomically newTChan
	otc <- liftBase $ atomically newTChan
	otc' <- liftBase $ atomically newTChan
	void . liftBaseDiscard forkIO . runPipe_ $ fromTChan otc
		=$= talk lock h addr pth gp
		=$= setDuration dr gdr
		=$= toTChan inc
	void . liftBaseDiscard forkIO . runPipe_ $ fromTChan otc'
		=$= talk lock h addr pth gp
		=$= setDuration dr gdr
		=$= toTChan inc'
	void . liftBaseDiscard forkIO . forever $ do
		d <- liftBase . atomically $ do
			md <- readTVar dr
			case md of
				Just d -> return d
				_ -> retry
		liftBase $ threadDelay d -- 10000000
--		liftBase . atomically $ readTChan lock
		liftBase $ polling pl ip inc' inc otc'
--		liftBase . atomically $ writeTChan lock ()
{-
	void . liftBaseDiscard forkIO . forever $ do
		liftBase . atomically $ readTChan lock
		liftBase . atomically $ readTChan inc >>= writeTChan inc'
		liftBase . atomically $ writeTChan lock ()
		-}
	return (inc, otc)

setDuration dr gdr = (await >>=) . maybe (return ()) $ \n -> case gdr n of
	Just d -> do
		lift . liftBase . atomically $ writeTVar dr (Just d)
		yield n >> setDuration dr gdr
	_ -> yield n >> setDuration dr gdr

polling :: XmlNode -> (XmlNode -> Bool) ->
	TChan XmlNode -> TChan XmlNode -> TChan XmlNode -> IO ()
polling pl ip i i' o = do
	atomically $ writeTChan o pl
--	threadDelay 1000000
	r <- atomically $ readTChan i
--	putStr "\n"
--	print $ ip r
	hFlush stdout
	if ip r
	then atomically (writeTChan i' r) >> polling pl ip i i' o
	else return ()

talk :: (MonadBase IO (HandleMonad h), HandleLike h) => TChan () -> h -> String ->
	FilePath -> (XmlNode -> FilePath) -> Pipe XmlNode XmlNode (HandleMonad h) ()
talk lock h addr pth gp = (await >>=) . (maybe (return ())) $ \n -> do
	let m = LBS.fromChunks [xmlString [n]]
	lift . liftBase . atomically $ readTChan lock
	r <- lift . request h $ post addr 80 (pth ++ "/" ++ gp n) (Nothing, m)
	void $ return ()
		=$= responseBody r
		=$= xmlEvent
		=$= convert fromJust
		=$= xmlNode []
	lift . liftBase . atomically $ writeTChan lock ()
	talk lock h addr pth gp
