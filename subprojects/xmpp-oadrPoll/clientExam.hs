{-# LANGUAGE OverloadedStrings, QuasiQuotes #-}

module Main (main) where

import Prelude hiding (drop, filter)

import System.IO
import System.Exit
import Control.Applicative
import Control.Monad
import Control.Monad.IO.Class
import Data.Conduit
import Network

import Data.XML.Types
import Text.XML

import qualified Data.ByteString as BS

import TlsClient

import XmppClient

import Text.Hamlet.XML

import Data.X509.File
import Data.X509.CertificateStore

oadrPoll :: Data.XML.Types.Element
[Data.XML.Types.NodeElement oadrPoll] = map toXMLNode [xml|

<oadr:oadrPoll ei:schemaVersion="2.0b">
    <ei:venID>VEN_123

|]

main :: IO ()
main = do
	h <- connectTo "localhost" (PortNumber 5222)
	cs <- makeCertificateStore <$> readSignedObject "cacert.pem"
	BS.hPut h $ beginDoc +++ stream
	hPutStr h starttls
	replicateM_ 12 . toTagEnd $ hGetChar h
	tls <- openTlsServer [] cs h
	connectSendIq tls oadrPoll
--	connectSendMsg tls "hogerunokai"
	putStrLn "Finished"

starttls :: String
starttls = "<starttls xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"/>"

toTagEnd :: IO Char -> IO ()
toTagEnd io = do
	c <- io
	putChar c
	if c == '>' then return () else toTagEnd io

checkEnd :: Handle -> Conduit Event IO Event
checkEnd h = do
	me <- await
	liftIO $ print me
	case me of
		Just (EventEndElement (Name "stream" _ _)) -> do
			liftIO $ do
				putStrLn "End stream"
				hClose h
				exitSuccess
		Just e -> do
			yield e
			checkEnd h
		_ -> return ()

beginDoc, stream :: BS.ByteString
beginDoc = "<?xml version=\"1.0\"?>"
stream = "<stream:stream to=\"localhost\" xml:lang=\"en\" version=\"1.0\" " +++
	"xmlns=\"jabber:client\" " +++
	"xmlns:stream=\"http://etherx.jabber.org/streams\">"

(+++) :: BS.ByteString -> BS.ByteString -> BS.ByteString
(+++) = BS.append
