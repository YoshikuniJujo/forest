{-# LANGUAGE OverloadedStrings, TupleSections, ScopedTypeVariables,
	TypeFamilies, FlexibleContexts, PackageImports #-}

import Prelude hiding (filter)

import Control.Monad
import Control.Concurrent hiding (yield)
import Data.Maybe
import Data.Pipe
import Data.Pipe.ByteString
import System.IO
import Text.XML.Pipe
import Network

import Push

main :: IO ()
main = do
	soc <- listenOn $ PortNumber 80
	forever $ do
		(sh, _, _) <- accept soc
		ch <- connectTo "localhost" $ PortNumber 8080
		(hp :: HttpPush Handle) <- generate (Two ch sh) ()
		void . forkIO . runPipe_ $ readFrom hp
			=$= convert (xmlString . (: []))
			=$= toHandle stdout
		void . forkIO . runPipe_ $ fromHandle stdin
			=$= xmlEvent
			=$= convert fromJust
			=$= xmlNode []
			=$= convert Just
			=$= writeTo hp
