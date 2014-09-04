{-# LANGUAGE TypeFamilies, FlexibleContexts,
	PackageImports #-}

module HttpPullCl (
	HttpPullCl, One(..), testPusher,
	) where

import Prelude hiding (filter)

import Control.Monad
import "monads-tf" Control.Monad.Trans
import Control.Monad.Base
import Control.Monad.Trans.Control
import Control.Concurrent
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

data HttpPullCl h = HttpPullCl
	(Pipe () XmlNode (HandleMonad h) ())
	(Pipe XmlNode () (HandleMonad h) ())

instance XmlPusher HttpPullCl where
	type NumOfHandle HttpPullCl = One
	type PusherArg HttpPullCl = (String, FilePath, XmlNode)
	type PushedType HttpPullCl = Bool
	generate = makeHttpPull
	readFrom (HttpPullCl r _) = r
	writeTo (HttpPullCl _ w) = filter isJust
		=$= convert (fst . fromJust)
		=$= w

makeHttpPull :: (HandleLike h, MonadBaseControl IO (HandleMonad h)) =>
	One h -> (String, FilePath, XmlNode) -> HandleMonad h (HttpPullCl h)
makeHttpPull (One h) (hn, fp, pl) = do
	(inc, otc) <- talkC h hn fp pl
	return $ HttpPullCl (fromTChan inc) (toTChan otc)

talkC :: (HandleLike h, MonadBaseControl IO (HandleMonad h)) =>
	h -> String ->
	FilePath -> XmlNode -> HandleMonad h (TChan XmlNode, TChan XmlNode)
talkC h addr pth pl = do
	inc <- liftBase $ atomically newTChan
	otc <- liftBase $ atomically newTChan
	void . liftBaseDiscard forkIO . runPipe_ $ fromTChan otc
		=$= talk h addr pth
		=$= toTChan inc
	void . liftBaseDiscard forkIO . forever $ do
		liftBase $ threadDelay 15000000
		liftBase . atomically $ writeTChan otc pl
	return (inc, otc)

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
