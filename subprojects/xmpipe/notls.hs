{-# LANGUAGE OverloadedStrings, PackageImports #-}

import Control.Monad
import "monads-tf" Control.Monad.Trans
import Data.Maybe
import Data.Pipe
import Data.HandleLike
import System.IO
import Text.XML.Pipe
import Network

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64

import Papillon
import Digest

main :: IO ()
main = do
	h <- connectTo "localhost" (PortNumber 54492)
	BS.hPut h $ xmlString begin
	BS.hPut h $ xmlString selectDigestMd5
	void . runPipe $ handleP h
		=$= xmlEvent
		=$= convert fromJust
--		=$= (xmlBegin >>= xmlNode)
		=$= xmlPipe
		=$= convert showResponse
		=$= processResponse h
		=$= printP

xmlPipe :: Monad m => Pipe XmlEvent XmlNode m ()
xmlPipe = do
	c <- xmlBegin >>= xmlNode
	when c $ xmlPipe

data ShowResponse
	= SRChallenge {
		realm :: BS.ByteString,
		nonce :: BS.ByteString,
		qop :: BS.ByteString,
		charset :: BS.ByteString,
		algorithm :: BS.ByteString }
	| SRChallengeRspauth BS.ByteString
	| SRSaslSuccess
	| SRRaw XmlNode
	deriving Show

showResponse :: XmlNode -> ShowResponse
showResponse (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "challenge")
	_ [] [XmlCharData c]) = let
		Right d = B64.decode c
		Just a = parseAtts d in
		case a of
			[("rspauth", ra)] -> SRChallengeRspauth ra
			_ -> SRChallenge {
				realm = fromJust $ lookup "realm" a,
				nonce = fromJust $ lookup "nonce" a,
				qop = fromJust $ lookup "qop" a,
				charset = fromJust $ lookup "charset" a,
				algorithm = fromJust $ lookup "algorithm" a }
showResponse (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "success")
	_ [] []) = SRSaslSuccess
showResponse n = SRRaw n

processResponse :: Handle -> Pipe ShowResponse ShowResponse IO ()
processResponse h = do
	mr <- await
	case mr of
		Just r -> lift (procR h r) >> yield r >> processResponse h
		_ -> return ()

procR :: Handle -> ShowResponse -> IO ()
procR h (SRChallenge r n q c a) = do
	print (r, n, q, c, a)
	let ret = kvsToS $ responseToKvs DR {
				drUserName = "yoshikuni",
				drRealm = r,
				drPassword = "password",
				drCnonce = "00DEADBEEF00",
				drNonce = n,
				drNc = "00000001",
				drQop = q,
				drDigestUri = "xmpp/localhost",
				drCharset = c }
	let node = xmlString . (: []) $ XmlNode
		(("", Nothing), "response")
		[("", "urn:ietf:params:xml:ns:xmpp-sasl")] []
		[XmlCharData $ encode ret]
	print ret
	print node
	BS.hPut h node
procR h (SRChallengeRspauth _) = do
	BS.hPut h . xmlString . (: []) $ XmlNode
		(("", Nothing), "response")
		[("", "urn:ietf:params:xml:ns:xmpp-sasl")] [] []
procR h SRSaslSuccess = BS.hPut h $ xmlString begin
procR h r = return ()

begin :: [XmlNode]
begin = [
	XmlDecl (1, 0),
	XmlStart (("stream", Nothing), "stream")
		[	("", "jabber:client"),
			("stream", "http://etherx.jabber.org/streams") ]
		[	((("", Nothing), "to"), "localhost"),
			((("", Nothing), "version"), "1.0"),
			((("xml", Nothing), "lang"), "en") ] ]

selectDigestMd5 :: [XmlNode]
selectDigestMd5 = (: []) $ XmlNode (("", Nothing), "auth")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")]
	[((("", Nothing), "mechanism"), "DIGEST-MD5")] []

handleP :: HandleLike h => h -> Pipe () BS.ByteString (HandleMonad h) ()
handleP h = do
	c <- lift $ hlGetContent h
	yield c
	handleP h

printP :: (Show a, Monad m, MonadIO m) => Pipe a () m ()
printP = await >>= maybe (return ()) (\x -> liftIO (print x) >> printP)

convert :: Monad m => (a -> b) -> Pipe a b m ()
convert f = await >>= maybe (return ()) (\x -> yield (f x) >> convert f)
