{-# LANGUAGE OverloadedStrings #-}

import Control.Applicative
import System.IO
import System.Environment
import Network
import Network.XMPiPe.Core.C2S.Client

import qualified Data.ByteString.Char8 as BSC

import Xmpp

newtype NeedResponse = NeedResponse Bool deriving Show

instance XmppPushType NeedResponse where
	needResponse (NeedResponse nr) = nr

main :: IO ()
main = do
	me : ps : you : _ <- map BSC.pack <$> getArgs
	h <- connectTo "localhost" $ PortNumber 5222
	testPusher (undefined :: Xmpp NeedResponse Handle) (One h)
		(XmppArgs ["SCRAM-SHA-1", "DIGEST-MD5"] (toJid me) ps (toJid you))
		(NeedResponse True)
