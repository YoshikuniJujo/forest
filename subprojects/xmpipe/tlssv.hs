{-# LANGUAGE OverloadedStrings, TupleSections, PackageImports #-}

import Control.Applicative
import "monads-tf" Control.Monad.State
import Data.Maybe
import Data.Pipe
import Data.HandleLike
import Text.XML.Pipe
import Network
import Network.PeyoTLS.Server
import Network.PeyoTLS.ReadFile
import "crypto-random" Crypto.Random

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

import Server

main :: IO ()
main = do
	k <- readKey "localhost.sample_key"
	c <- readCertificateChain ["localhost.sample_crt"]
	g0 <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	soc <- listenOn $ PortNumber 5222
	void . (`runStateT` g0) . forever $ do
		(h, _, _) <- liftIO $ accept soc
		g <- StateT $ return . cprgFork
		liftIO . hlPut h . xmlString $ begin ++ tlsFeatures
		voidM . liftIO . runPipe $ handleP h
			=$= xmlEvent
			=$= convert fromJust
			=$= (xmlBegin >>= xmlNodeUntil isStarttls)
			=$= printP h
		liftIO $ hlDebug h "critical" "proceed\n"
		liftIO . hlPut h . xmlString $ proceed
		liftIO . (`run` g) $ do
			p <- open h ["TLS_RSA_WITH_AES_128_CBC_SHA"] [(k, c)] Nothing
			(`evalStateT` (0 :: Int)) . xmpp $ SHandle p
--			hlGet p 10 >>= liftIO . print

isStarttls :: XmlNode -> Bool
isStarttls (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-tls"), "starttls")
	_ [] []) = True
isStarttls _ = False

begin :: [XmlNode]
begin = [
	XmlDecl (1, 0),
	XmlStart (("stream", Nothing), "stream")
		[	("", "jabber:client"),
			("stream", "http://etherx.jabber.org/streams") ]
		[	(nullQ "id", "83e074ac-c014-432e9f21-d06e73f5777e"),
			(nullQ "from", "localhost"),
			(nullQ "version", "1.0"),
			((("xml", Nothing), "lang"), "en") ]
	]

tlsFeatures :: [XmlNode]
tlsFeatures =
	[XmlNode (("stream", Nothing), "features") [] [] [mechanisms, starttls]]

mechanisms :: XmlNode
mechanisms = XmlNode (nullQ "mechanisms")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")] []
	[	XmlNode (nullQ "mechanism") [] [] [XmlCharData "SCRAM-SHA-1"],
	 	XmlNode (nullQ "mechanism") [] [] [XmlCharData "DIGEST-MD5"] ]

starttls :: XmlNode
starttls = XmlNode (nullQ "starttls")
	[("", "urn:ietf:params:xml:ns:xmpp-tls")] [] []

proceed :: [XmlNode]
proceed = (: []) $ XmlNode (nullQ "proceed")
	[("", "urn:ietf:params:xml:ns:xmpp-tls")] [] []

voidM :: Monad m => m a -> m ()
voidM = (>> return ())

handleP :: HandleLike h => h -> Pipe () BS.ByteString (HandleMonad h) ()
handleP h = do
	c <- lift $ hlGetContent h
	yield c
	handleP h

printP :: (Show a, HandleLike h) => h -> Pipe a () (HandleMonad h) ()
printP h = await >>=
	maybe (return ()) (\x -> lift (hlDebug h "critical" $ showBS x) >> printP h)

showBS :: Show a => a -> BS.ByteString
showBS = BSC.pack . (++ "\n") . show

convert :: Monad m => (a -> b) -> Pipe a b m ()
convert f = await >>= maybe (return ()) (\x -> yield (f x) >> convert f)

nullQ :: BS.ByteString -> QName
nullQ = (("", Nothing) ,)
