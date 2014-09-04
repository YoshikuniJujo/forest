{-# LANGUAGE OverloadedStrings #-}

import Control.Monad
import Control.Concurrent
import System.IO
import Text.XML.Pipe
import Network

import HttpPullTlsSv

main :: IO ()
main = do
	soc <- listenOn $ PortNumber 443
	forever $ do
		(h, _, _) <- accept soc
		void . forkIO $ testPusher
			(undefined :: HttpPullTlsSv Handle) (One h) isPoll True

isPoll :: XmlNode -> Bool
isPoll (XmlNode (_, "poll") _ _ _) = True
isPoll _ = False
