{-# LANGUAGE TupleSections, TypeFamilies, FlexibleContexts, PackageImports #-}

module TestPusher (XmlPusher(..), Zero(..), One(..), Two(..), testPusher) where

import Control.Monad
import Control.Concurrent
import Data.Maybe
import Data.Pipe
import Data.Pipe.ByteString
import System.IO
import Text.XML.Pipe

import XmlPusher

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
