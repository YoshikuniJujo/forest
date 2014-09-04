{-# LANGUAGE OverloadedStrings #-}

import System.IO
import Text.XML.Pipe
import Network

import HttpPullCl

main :: IO ()
main = do
	h <- connectTo "localhost" $ PortNumber 80
	testPusher (undefined :: HttpPullCl () Handle) (One h)
		(HttpPullClArgs "localhost" "/" (XmlNode (nullQ "poll") [] [] []))
		()
