{-# LANGUAGE OverloadedStrings #-}

import System.IO
import Text.XML.Pipe
import Network

import HttpPullTlsCl

main :: IO ()
main = do
	h <- connectTo "localhost" $ PortNumber 443
	testPusher (undefined :: HttpPullTlsCl Handle) (One h)
		(HttpPullTlsClArgs "localhost" "/"
			(XmlNode (nullQ "poll") [] [] []))
		True
