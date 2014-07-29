{-# LANGUAGE OverloadedStrings, TupleSections, PackageImports #-}

import Control.Monad
import "monads-tf" Control.Monad.Trans
import Control.Concurrent (forkIO)
import Data.Maybe
import Data.Pipe
import Data.HandleLike
import Text.XML.Pipe
import Network

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Base64 as B64

import DigestSv

main :: IO ()
main = do
	socket <- listenOn $ PortNumber 5222
	forever $ do
		(h, _, _) <- accept socket
		voidM . forkIO $ xmpp h

xmpp :: HandleLike h => h -> HandleMonad h ()
xmpp h = do
	hlPut h . xmlString $ begin ++ authFeatures
	hlPut h . xmlString $ challengeXml
	voidM . runPipe $ handleP h
		=$= xmlEvent
		=$= convert fromJust
		=$= (xmlBegin >>= xmlNode)
		=$= convert showResponse
		=$= processResponse h
		=$= printP h

data ShowResponse
	= SRResponse BS.ByteString
	| SRResponseNull
	| SRRaw XmlNode
	deriving Show

showResponse :: XmlNode -> ShowResponse
showResponse (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "response")
	_ [] []) = SRResponseNull
showResponse (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "response")
	_ [] [XmlCharData cd]) = SRResponse . (\(Right s) -> s) $ B64.decode cd
showResponse n = SRRaw n

processResponse :: HandleLike h =>
	h -> Pipe ShowResponse ShowResponse (HandleMonad h) ()
processResponse h = do
	mr <- await
	case mr of
		Just r -> lift (procR h r) >> yield r >> processResponse h
		_ -> return ()

procR :: HandleLike h => h -> ShowResponse -> HandleMonad h ()
procR h (SRResponse _) = do
	let sret = B64.encode . fromJust . lookup "response" $
		responseToKvs False sampleDR
	hlPut h . xmlString . (: []) $ XmlNode (nullQ "challenge")
		[("", "urn:ietf:params:xml:ns:xmpp-sasl")] [] [XmlCharData sret]
	hlDebug h "critical" $ sret `BS.append` "\n"
procR _ _ = return ()

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

voidM :: Monad m => m a -> m ()
voidM = (>> return ())

nullQ :: BS.ByteString -> QName
nullQ = (("", Nothing) ,)

begin :: [XmlNode]
begin = [
	XmlDecl (1, 0),
	XmlStart (("stream", Nothing), "stream")
		[	("", "jabber:client"),
			("stream", "http://etherx.jabber.org/streams") ]
		[	(nullQ "id", "83e074ac-c014-432e-9f21-d06e73f5777e"),
			(nullQ "from", "localhost"),
			(nullQ "version", "1.0"),
			((("xml", Nothing), "lang"), "en") ]
	]

authFeatures :: [XmlNode]
authFeatures = [XmlNode (("stream", Nothing), "features") [] [] [mechanisms]]

mechanisms :: XmlNode
mechanisms = XmlNode (nullQ "mechanisms")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")] []
	[	XmlNode (nullQ "mechanism") [] [] [XmlCharData "SCRAM-SHA-1"],
		XmlNode (nullQ "mechanism") [] [] [XmlCharData "DIGEST-MD5"] ]

convert :: Monad m => (a -> b) -> Pipe a b m ()
convert f = await >>= maybe (return ()) (\x -> yield (f x) >> convert f)

challengeXml :: [XmlNode]
challengeXml = (: []) $ XmlNode
	(nullQ "challenge") [("", "urn:ietf:params:xml:ns:xmpp-sasl")] []
	[XmlCharData challenge]

challenge :: BS.ByteString
challenge = B64.encode $ BS.concat [
	"realm=\"localhost\",",
	"nonce=\"90972262-92fe-451d-9526-911f5b8f6e34\",",
	"qop=\"auth\",",
	"charset=utf-8,",
	"algorithm=md5-sess" ]
