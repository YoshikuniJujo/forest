{-# LANGUAGE OverloadedStrings #-}

import Control.Applicative
import System.IO
import System.Environment
import Text.XML.Pipe
import Network
import Network.XMPiPe.Core.C2S.Client

import qualified Data.ByteString.Char8 as BSC

import Xmpp

main :: IO ()
main = do
	me : ps : you : _ <- map BSC.pack <$> getArgs
	h <- connectTo "localhost" $ PortNumber 5222
	testPusher (undefined :: Xmpp Handle) (One h)
		(XmppArgs ["SCRAM-SHA-1", "DIGEST-MD5"] wntRspns iNdRspns
			(toJid me) ps (toJid you))

wntRspns :: XmlNode -> Bool
wntRspns (XmlNode (_, "monologue") _ [] []) = False
wntRspns (XmlNode (_, "message") _ [] []) = False
wntRspns _ = True

iNdRspns :: XmlNode -> Bool
iNdRspns (XmlNode (_, "message") _ [] []) = False
iNdRspns _ = True
