{-# LANGUAGE TypeFamilies, FlexibleContexts #-}

module XmlPusher (
	XmlPusher(..), SimplePusher,
	) where

import Prelude hiding (filter)

import Control.Monad
import Control.Monad.Base
import Control.Monad.Trans.Control
import Control.Concurrent
import Data.Maybe
import Data.HandleLike
import Data.Pipe
import Data.Pipe.Flow
import Data.Pipe.ByteString
import System.IO
import Text.XML.Pipe
import Network.PeyoTLS.Client

class XmlPusher xp where
	type PusherArg xp
	type NumOfHandle xp :: * -> *
	generate :: (ValidateHandle h, MonadBaseControl IO (HandleMonad h)) =>
		NumOfHandle xp h -> PusherArg xp -> HandleMonad h (xp h)
	readFrom :: (HandleLike h, MonadBase IO (HandleMonad h)) =>
		xp h -> Pipe () XmlNode (HandleMonad h) ()
	writeTo :: (HandleLike h, MonadBase IO (HandleMonad h)) =>
		xp h -> Pipe (Maybe (XmlNode, Bool)) () (HandleMonad h) ()

data SimplePusher h = SimplePusher
	(Pipe () XmlNode (HandleMonad h) ())
	(Pipe (Maybe (XmlNode, Bool)) () (HandleMonad h) ())

data Zero a = Zero deriving Show

instance XmlPusher SimplePusher where
	type PusherArg SimplePusher = ()
	type NumOfHandle SimplePusher = Zero
	generate = const $ const simplePusher

simplePusher :: MonadBaseControl IO (HandleMonad h) =>
	HandleMonad h (SimplePusher h)
simplePusher = return $ SimplePusher readXml writeXml

readXml :: MonadBase IO m => Pipe () XmlNode m ()
readXml = fromHandle stdin
	=$= xmlEvent
	=$= convert fromJust
	=$= (xmlNode [] >> return ())

writeXml :: MonadBase IO m => Pipe (Maybe (XmlNode, Bool))  () m ()
writeXml = filter isJust
	=$= convert (xmlString . (: []) . fst . fromJust)
	=$= toHandle stdout

testPusher :: XmlPusher xp => xp Handle ->
	NumOfHandle xp Handle -> PusherArg xp -> IO ()
testPusher tp hs as = do
	xp <- generate hs as >>= return . (`asTypeOf` tp)
	void . forkIO . runPipe_ $ readFrom xp
		=$= convert (xmlString . (: []))
		=$= toHandle stdout
