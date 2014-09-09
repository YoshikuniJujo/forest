{-# LANGUAGE TupleSections, TypeFamilies, FlexibleContexts,
	PackageImports #-}

module XmlPusher (
	XmlPusher(..), SimplePusher, Zero(..), One(..), Two(..),
	testPusher,
	) where

import Prelude hiding (filter)

import Control.Monad
import "monads-tf" Control.Monad.Error
import Control.Monad.Base
import Control.Monad.Trans.Control
import Control.Concurrent
import Data.Maybe
import Data.HandleLike
import Data.Pipe
import Data.Pipe.ByteString
import System.IO
import Text.XML.Pipe
import Network.PeyoTLS.Client

class XmlPusher xp where
	type PusherArg xp
	type NumOfHandle xp :: * -> *
	generate :: (
		ValidateHandle h,
		MonadBaseControl IO (HandleMonad h),
		MonadError (HandleMonad h), Error (ErrorType (HandleMonad h))
		) =>
		NumOfHandle xp h -> PusherArg xp -> HandleMonad h (xp h)
	readFrom :: (HandleLike h, MonadBase IO (HandleMonad h)) =>
		xp h -> Pipe () XmlNode (HandleMonad h) ()
	writeTo :: (HandleLike h, MonadBase IO (HandleMonad h)) =>
		xp h -> Pipe XmlNode () (HandleMonad h) ()

data SimplePusher h = SimplePusher
	(Pipe () XmlNode (HandleMonad h) ())
	(Pipe XmlNode () (HandleMonad h) ())

data Zero a = Zero deriving Show
data One a = One a deriving Show
data Two a = Two a a deriving Show

instance XmlPusher SimplePusher where
	type PusherArg SimplePusher = (FilePath, FilePath)
	type NumOfHandle SimplePusher = Zero
	generate = const $ uncurry simplePusher
	readFrom (SimplePusher r _) = r
	writeTo (SimplePusher _ w) = w

simplePusher :: MonadBaseControl IO (HandleMonad h) =>
	FilePath -> FilePath -> HandleMonad h (SimplePusher h)
simplePusher rf wf = return $ SimplePusher (readXml rf) (writeXml wf)

readXml :: MonadBaseControl IO m => FilePath -> Pipe () XmlNode m ()
readXml rf = fromFile rf
	=$= xmlEvent
	=$= convert fromJust
	=$= (xmlNode [] >> return ())

writeXml :: MonadBaseControl IO m => FilePath -> Pipe XmlNode () m ()
writeXml wf = convert (xmlString . (: []))  =$= toFile wf

testPusher :: XmlPusher xp =>
	xp Handle -> NumOfHandle xp Handle -> PusherArg xp -> IO ()
testPusher tp hs as = do
	xp <- generate hs as >>= return . (`asTypeOf` tp)
	void . forkIO . runPipe_ $ readFrom xp
		=$= convert (xmlString . (: []))
		=$= toHandle stdout
	runPipe_ $ fromHandle stdin
		=$= xmlEvent
		=$= convert fromJust
		=$= xmlNode []
		=$= writeTo xp
