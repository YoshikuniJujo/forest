{-# LANGUAGE OverloadedStrings #-}

import System.IO
import Text.XML.Pipe
import Network

import HttpPushTls

main :: IO ()
main = do
	ch <- connectTo "localhost" $ PortNumber 80
	soc <- listenOn $ PortNumber 8080
	(sh, _, _) <- accept soc
	testPusher (undefined :: HttpPushTls Handle) (Two ch sh)
		(HttpPushTlsArgs "" gtPth wntRspns)
		True

wntRspns :: XmlNode -> Bool
wntRspns (XmlNode (_, "monologue") _ [] []) = False
wntRspns _ = True

gtPth :: XmlNode -> FilePath
gtPth (XmlNode (_, "father") _ [] []) = "family"
gtPth _ = "others"
