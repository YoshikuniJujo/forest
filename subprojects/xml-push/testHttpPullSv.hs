{-# LANGUAGE OverloadedStrings #-}

import Control.Monad
import Control.Concurrent
import System.IO
import Text.XML.Pipe
import Network

import HttpPullSv

main :: IO ()
main = do
	soc <- listenOn $ PortNumber 80
	forever $ do
		(h, _, _) <- accept soc
		void . forkIO $ testPusher
			(undefined :: HttpPullSv Handle) (One h) (isPoll, endPoll)

isPoll :: XmlNode -> Bool
isPoll (XmlNode (_, "poll") _ _ _) = True
isPoll _ = False

endPoll :: XmlNode
endPoll = XmlNode (nullQ "nothing") [] [] []
