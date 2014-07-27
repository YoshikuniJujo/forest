{-# LANGUAGE OverloadedStrings, PackageImports #-}

import Control.Arrow
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
	= SRStream [(Tag, BS.ByteString)]
	| SRFeatures [Feature]
	| SRChallenge {
		realm :: BS.ByteString,
		nonce :: BS.ByteString,
		qop :: BS.ByteString,
		charset :: BS.ByteString,
		algorithm :: BS.ByteString }
	| SRChallengeRspauth BS.ByteString
	| SRSaslSuccess
	| SRRaw XmlNode
	deriving Show

data Feature
	= Mechanisms [Mechanism]
	| Caps {ctHash :: BS.ByteString,
		ctNode :: BS.ByteString,
		ctVer :: BS.ByteString } -- [(CapsTag, BS.ByteString)]
	| Rosterver Requirement
	| Bind Requirement
	| Session Requirement
	| FeatureRaw XmlNode
	deriving Show

toFeature :: XmlNode -> Feature
toFeature (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "mechanisms")
	_ [] ns) = Mechanisms $ map toMechanism ns
toFeature (XmlNode ((_, Just "http://jabber.org/protocol/caps"), "c") _ as []) =
	let h = map (first toCapsTag) as in Caps {
		ctHash = fromJust $ lookup CTHash h,
		ctNode = fromJust $ lookup CTNode h,
		ctVer = (\(Right r) -> r) . B64.decode . fromJust $ lookup CTVer h }
--	Caps $ map (first toCapsTag) as
toFeature (XmlNode ((_, Just "urn:xmpp:features:rosterver"), "ver") _ [] r) =
	Rosterver $ toRequirement r
toFeature (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-bind"), "bind") _ [] r) =
	Bind $ toRequirement r
toFeature (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-session"), "session")
	_ [] r) = Session $ toRequirement r
toFeature n = FeatureRaw n

data Requirement = Optional | Required | NoRequirement [XmlNode]
	deriving (Eq, Show)

toRequirement :: [XmlNode] -> Requirement
toRequirement [XmlNode (_, "optional") _ [] []] = Optional
toRequirement [XmlNode (_, "required") _ [] []] = Required
toRequirement n = NoRequirement n

data Mechanism = ScramSha1 | DigestMd5 | MechanismRaw XmlNode deriving Show

toMechanism :: XmlNode -> Mechanism
toMechanism (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "mechanism")
	_ [] [XmlCharData "SCRAM-SHA-1"]) = ScramSha1
toMechanism (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "mechanism")
	_ [] [XmlCharData "DIGEST-MD5"]) = DigestMd5
toMechanism n = MechanismRaw n

data Tag = Id | From | Version | Lang | TagRaw QName deriving (Eq, Show)

qnameToTag :: QName -> Tag
qnameToTag ((_, Just "jabber:client"), "id") = Id
qnameToTag ((_, Just "jabber:client"), "from") = From
qnameToTag ((_, Just "jabber:client"), "version") = Version
qnameToTag (("xml", Nothing), "lang") = Lang
qnameToTag n = TagRaw n

data CapsTag = CTHash | CTNode | CTVer | CTRaw QName deriving (Eq, Show)

toCapsTag :: QName -> CapsTag
toCapsTag ((_, Just "http://jabber.org/protocol/caps"), "hash") = CTHash
toCapsTag ((_, Just "http://jabber.org/protocol/caps"), "ver") = CTVer
toCapsTag ((_, Just "http://jabber.org/protocol/caps"), "node") = CTNode
toCapsTag n = CTRaw n

showResponse :: XmlNode -> ShowResponse
showResponse (XmlStart ((_, Just "http://etherx.jabber.org/streams"), "stream")
	_ atts) = SRStream $ map (first qnameToTag) atts
showResponse (XmlNode ((_, Just "http://etherx.jabber.org/streams"), "features")
	_ [] nds) = SRFeatures $ map toFeature nds
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
procR h (SRChallenge r n q c _a) = do
--	print (r, n, q, c, a)
	let dr = DR {	drUserName = "yoshikuni",
			drRealm = r,
			drPassword = "password",
			drCnonce = "00DEADBEEF00",
			drNonce = n,
			drNc = "00000001",
			drQop = q,
			drDigestUri = "xmpp/localhost",
			drCharset = c }
	let ret = kvsToS $ responseToKvs True dr
	let Just sret = lookup "response" $ responseToKvs False dr
	let node = xmlString . (: []) $ XmlNode
		(("", Nothing), "response")
		[("", "urn:ietf:params:xml:ns:xmpp-sasl")] []
		[XmlCharData $ encode ret]
--	print ret
	print sret
--	print node
	BS.hPut h node
procR h (SRChallengeRspauth _) = do
	BS.hPut h . xmlString . (: []) $ XmlNode
		(("", Nothing), "response")
		[("", "urn:ietf:params:xml:ns:xmpp-sasl")] [] []
procR h SRSaslSuccess = BS.hPut h $ xmlString begin
procR _ _ = return ()

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
