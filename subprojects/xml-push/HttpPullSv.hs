{-# LANGUAGE TypeFamilies, FlexibleContexts,
	PackageImports #-}

module HttpPullSv (
	HttpPullSv, One(..), testPusher,
	) where

import Prelude hiding (filter)

import "monads-tf" Control.Monad.Trans
import Control.Monad.Base
import Control.Monad.Trans.Control
import Control.Concurrent hiding (yield)
import Control.Concurrent.STM
import Data.Maybe
import Data.HandleLike
import Data.Pipe
import Data.Pipe.List
import Data.Pipe.TChan
import Text.XML.Pipe
import Network.TigHTTP.Server
import Network.TigHTTP.Types

import qualified Data.ByteString.Lazy as LBS

import XmlPusher

data HttpPullSv h = HttpPullSv
	(Pipe () XmlNode (HandleMonad h) ())
	(Pipe XmlNode () (HandleMonad h) ())

instance XmlPusher HttpPullSv where
	type NumOfHandle HttpPullSv = One
	type PusherArg HttpPullSv = (XmlNode -> Bool, XmlNode)
	type PushedType HttpPullSv = Bool
	generate = makeHttpPull
	readFrom (HttpPullSv r _) = r
	writeTo (HttpPullSv _ w) = convert fst =$= w

makeHttpPull :: (HandleLike h, MonadBaseControl IO (HandleMonad h)) =>
	One h -> (XmlNode -> Bool, XmlNode) -> HandleMonad h (HttpPullSv h)
makeHttpPull (One h) (ip, ep) = do
	(inc, otc) <- run h ip ep
	return $ HttpPullSv (fromTChan inc) (toTChan otc)

run :: (HandleLike h, MonadBaseControl IO (HandleMonad h)) =>
	h -> (XmlNode -> Bool) -> XmlNode ->
	HandleMonad h (TChan XmlNode, TChan XmlNode)
run h ip ep = do
	inc <- liftBase $ atomically newTChan
	otc <- liftBase $ atomically newTChan
	_ <- liftBaseDiscard forkIO . runPipe_ $ talk h ip ep inc otc
	return (inc, otc)

talk :: (HandleLike h, MonadBase IO (HandleMonad h)) =>
	h -> (XmlNode -> Bool) -> XmlNode ->
	TChan XmlNode -> TChan XmlNode -> Pipe () () (HandleMonad h) ()
talk h ip ep inc otc = do
	r <- lift $ getRequest h
	lift . liftBase . print $ requestPath r
	rns <- requestBody r
		=$= xmlEvent
		=$= convert fromJust
		=$= xmlNode []
		=$= toList
	if case rns of [n] -> ip n; _ -> False
	then (flushOr otc ep =$=) . (await >>=) . maybe (return ()) $ \n ->
		lift . putResponse h . responseP $ LBS.fromChunks [xmlString [n]]
	else do	mapM_ yield rns =$= toTChan inc
		(fromTChan otc =$=) . (await >>=) . maybe (return ()) $ \n ->
			lift . putResponse h . responseP
				$ LBS.fromChunks [xmlString [n]]
	talk h ip ep inc otc

responseP :: (HandleLike h, MonadBase IO (HandleMonad h)) =>
	LBS.ByteString -> Response Pipe h
responseP = response

flushOr :: MonadBase IO m => TChan XmlNode -> XmlNode -> Pipe () XmlNode m ()
flushOr c ep = do
	e <- lift . liftBase . atomically $ isEmptyTChan c
	lift . liftBase $ print e
	if e then yield ep else do
		po <- lift . liftBase . atomically $ readTChan c
		yield po
