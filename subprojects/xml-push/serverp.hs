{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts, ScopedTypeVariables,
	PackageImports #-}

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
import Data.Pipe.List
import Data.Pipe.TChan
import Data.Pipe.ByteString
import System.IO
import Text.XML.Pipe
import Network
import Network.TigHTTP.Server
import Network.TigHTTP.Types

import qualified Data.ByteString.Lazy as LBS

class XmlPusher xp where
	type PusherArg xp
	generate :: (HandleLike h, MonadBaseControl IO (HandleMonad h)
		) => h -> PusherArg xp -> HandleMonad h (xp h)
	readFrom :: HandleLike h => xp h -> Pipe () XmlNode (HandleMonad h) ()
	writeTo :: HandleLike h => xp h -> Pipe XmlNode () (HandleMonad h) ()

data HttpPull h = HttpPull
	(Pipe () XmlNode (HandleMonad h) ())
	(Pipe XmlNode () (HandleMonad h) ())

instance XmlPusher HttpPull where
	type PusherArg HttpPull = XmlNode -> Bool
	generate = makeHttpPull
	readFrom (HttpPull r _) = r
	writeTo (HttpPull _ w) = w

makeHttpPull :: (HandleLike h, MonadBaseControl IO (HandleMonad h)) =>
	h -> (XmlNode -> Bool) -> HandleMonad h (HttpPull h)
makeHttpPull h ip = do
	(inc, otc) <- run h ip
	return $ HttpPull (fromTChan inc) (toTChan otc)

isPoll :: XmlNode -> Bool
isPoll (XmlNode (_, "poll") _ _ _) = True
isPoll _ = False

main :: IO ()
main = do
	soc <- listenOn $ PortNumber 80
	forever $ do
		(h, _, _) <- accept soc
		void . forkIO $ do
			(hp :: HttpPull Handle) <- generate h isPoll
			void . forkIO $ runPipe_ $ readFrom hp
				=$= convert (xmlString . (: []))
				=$= toHandleLn stdout
			runPipe_ $ fromHandle stdin
				=$= xmlEvent
				=$= convert fromJust
				=$= xmlNode []
				=$= writeTo hp

run :: (HandleLike h, MonadBaseControl IO (HandleMonad h)) =>
	h -> (XmlNode -> Bool) -> HandleMonad h (TChan XmlNode, TChan XmlNode)
run h ip = do
	inc <- liftBase $ atomically newTChan
	otc <- liftBase $ atomically newTChan
	void . liftBaseDiscard forkIO . runPipe_ $ talk h ip inc otc
	return (inc, otc)

talk :: (HandleLike h, MonadBase IO (HandleMonad h)) => h -> (XmlNode -> Bool) ->
	TChan XmlNode -> TChan XmlNode -> Pipe () () (HandleMonad h) ()
talk h ip inc otc = do
	r <- lift $ getRequest h
	lift . liftBase . print $ requestPath r
	rns <- requestBody r
		=$= xmlEvent
		=$= convert fromJust
		=$= xmlNode []
		=$= toList
	if case rns of [n] -> ip n; _ -> False
	then (flushTChan otc =$=) . (await >>=) . maybe (return ()) $ \ns ->
		lift . putResponse h . responseP $ LBS.fromChunks [xmlString ns]
	else do	mapM_ yield rns =$= toTChan inc
		(fromTChan otc =$=) . (await >>=) . maybe (return ()) $ \n ->
			lift . putResponse h . responseP
				$ LBS.fromChunks [xmlString [n]]
	talk h ip inc otc

flushTChan :: MonadBase IO m => TChan a -> Pipe () [a] m ()
flushTChan c = lift (liftBase . atomically $ allTChan c) >>= yield

allTChan :: TChan s -> STM [s]
allTChan c = do
	e <- isEmptyTChan c
	if e then return [] else do
		x <- readTChan c
		(x :) <$> allTChan c

responseP :: HandleLike h => LBS.ByteString -> Response Pipe h
responseP = response
