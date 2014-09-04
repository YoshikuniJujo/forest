{-# LANGUAGE OverloadedStrings #-}

import Control.Applicative
import System.IO
import System.Environment
import Network
import Network.XMPiPe.Core.C2S.Client

import qualified Data.ByteString.Char8 as BSC

import XmppTls

main :: IO ()
main = do
	me : ps : you : _ <- map BSC.pack <$> getArgs
	h <- connectTo "localhost" $ PortNumber 5222
	testPusher (undefined :: XmppTls Handle) (One h) $ XmppTlsArgs
		["EXTERNAL", "SCRAM-SHA-1", "DIGEST-MD5", "PLAIN"]
		(toJid me) ps (toJid you)
