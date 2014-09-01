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

import PushP

main :: IO ()
main = do
	ch <- connectTo "localhost" $ PortNumber 80
	soc <- listenOn $ PortNumber 8080
	(sh, _, _) <- accept soc
	(hp :: HttpPush Handle) <- generate (Two ch sh) ()
	void . forkIO . runPipe_ $ readFrom hp
		=$= convert (xmlString . (: []))
		=$= toHandle stdout
	runPipe_ $ fromHandle stdin
		=$= xmlEvent
		=$= convert fromJust
		=$= xmlNode []
		=$= convert Just
		=$= writeTo hp
