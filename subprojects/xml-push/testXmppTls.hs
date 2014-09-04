{-# LANGUAGE OverloadedStrings #-}

import Control.Applicative
import System.IO
import System.Environment
import Network
import Network.XMPiPe.Core.C2S.Client
import Network.PeyoTLS.ReadFile

import qualified Data.ByteString.Char8 as BSC

import XmppTls

main :: IO ()
main = do
	me : ps : you : _ <- map BSC.pack <$> getArgs
	h <- connectTo "localhost" $ PortNumber 5222
	ca <- readCertificateStore ["certs/cacert.sample_pem"]
	k <- readKey "certs/yoshikuni.sample_key"
	c <- readCertificateChain ["certs/yoshiuni.sample_crt"]
	testPusher (undefined :: XmppTls Handle) (One h) (
		XmppArgs ["EXTERNAL", "SCRAM-SHA-1", "DIGEST-MD5", "PLAIN"]
			(toJid me) ps (toJid you),
		TlsArgs ca [(k, c)] )
		True
