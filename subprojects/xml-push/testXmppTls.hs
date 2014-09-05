{-# LANGUAGE OverloadedStrings #-}

import Control.Applicative
import System.IO
import System.Environment
import Text.XML.Pipe
import Network
import Network.XMPiPe.Core.C2S.Client
import Network.PeyoTLS.ReadFile

import qualified Data.ByteString.Char8 as BSC

import XmppTls

newtype NeedResponse = NeedResponse Bool deriving Show

instance XmppPushType NeedResponse where
	needResponse (NeedResponse nr) = nr

main :: IO ()
main = do
	me : ps : you : _ <- map BSC.pack <$> getArgs
	h <- connectTo "localhost" $ PortNumber 5222
	ca <- readCertificateStore ["certs/cacert.sample_pem"]
	k <- readKey "certs/yoshikuni.sample_key"
	c <- readCertificateChain ["certs/yoshikuni.sample_crt"]
	testPusher (undefined :: XmppTls NeedResponse Handle) (One h) (
		XmppArgs ["EXTERNAL", "SCRAM-SHA-1", "DIGEST-MD5", "PLAIN"]
			wntRspns iNdRspns (toJid me) ps (toJid you),
		TlsArgs ca [(k, c)] )
		(NeedResponse True)

wntRspns :: XmlNode -> Bool
wntRspns (XmlNode (_, "monologue") _ [] []) = False
wntRspns (XmlNode (_, "message") _ [] []) = False
wntRspns _ = True

iNdRspns :: XmlNode -> Bool
iNdRspns (XmlNode (_, "message") _ [] []) = False
iNdRspns _ = True
