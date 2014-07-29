{-# LANGUAGE OverloadedStrings, PackageImports #-}

import Control.Arrow
import Control.Monad
import "monads-tf" Control.Monad.Trans
import Data.Maybe
import Data.Pipe
import Data.HandleLike
import Text.XML.Pipe
import Network

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Base64 as B64

import Papillon
import Digest
import Caps (profanityCaps, capsToXml, capsToQuery)

import System.IO.Unsafe
import System.Environment

sender, recipient :: BS.ByteString
-- sender = "yoshikuni"
-- recipient = "yoshio"
[sender, recipient] = map BSC.pack $ unsafePerformIO getArgs

main :: IO ()
main = do
	h <- connectTo "localhost" (PortNumber 54492)
	xmpp h

xmpp :: HandleLike h => h -> HandleMonad h ()
xmpp h = do
	hlPut h $ xmlString begin
	hlPut h $ xmlString selectDigestMd5
	voidM . runPipe $ handleP h
		=$= xmlEvent
		=$= convert fromJust
--		=$= (xmlBegin >>= xmlNode)
		=$= xmlPipe
		=$= checkP h
		=$= convert showResponse
		=$= process
		=$= output h
--		=$= processResponse h
--		=$= printP h

checkP :: HandleLike h => h -> Pipe XmlNode XmlNode (HandleMonad h) ()
checkP h = do
	mn <- await
	case mn of
		Just n@(XmlNode (_, "challenge") _ _ [XmlCharData cd]) ->
			lift (hlDebug h "critical" . (`BS.append` "\n") .
					(\(Right s) -> s) $ B64.decode cd) >>
				yield n >> checkP h
		Just n -> yield n >> checkP h
		_ -> return ()

voidM :: Monad m => m a -> m ()
voidM m = m >> return ()

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
	| SRIq [(IqTag, BS.ByteString)] IqBody
	| SRPresence [(Tag, BS.ByteString)] Caps
	| SRMessage [(IqTag, BS.ByteString)] MessageBody MessageDelay MessageXDelay
	| SRRaw XmlNode
	deriving Show

data MessageBody
	= MessageBody BS.ByteString
	| MBRaw XmlNode
	deriving Show
data MessageDelay
	= MessageDelay [(DelayTag, BS.ByteString)]
	| MDRaw XmlNode
	deriving Show

data DelayTag = DTFrom | DTStamp | DlyTRaw QName deriving Show

data MessageXDelay
	= MessageXDelay [(XDelayTag, BS.ByteString)]
	| MXDRaw XmlNode
	deriving Show

data XDelayTag = XDTFrom | XDTStamp | XDlyTRaw QName deriving Show

toXDelay :: XmlNode -> MessageXDelay
toXDelay (XmlNode ((_, Just "jabber:x:delay"), "x") _ as []) =
	MessageXDelay $ map (first toXDelayTag) as
toXDelay n = MXDRaw n

toXDelayTag :: QName -> XDelayTag
toXDelayTag ((_, Just "jabber:x:delay"), "from") = XDTFrom
toXDelayTag ((_, Just "jabber:x:delay"), "stamp") = XDTStamp
toXDelayTag n = XDlyTRaw n

toDelayTag :: QName -> DelayTag
toDelayTag ((_, Just "urn:xmpp:delay"), "from") = DTFrom
toDelayTag ((_, Just "urn:xmpp:delay"), "stamp") = DTStamp
toDelayTag n = DlyTRaw n

toBody :: XmlNode -> MessageBody
toBody (XmlNode ((_, Just "jabber:client"), "body") _ [] [XmlCharData b]) =
	MessageBody b
toBody n = MBRaw n

toDelay :: XmlNode -> MessageDelay
toDelay (XmlNode ((_, Just "urn:xmpp:delay"), "delay") _ as []) = MessageDelay $
	map (first toDelayTag) as
toDelay n = MDRaw n

data Feature
	= Mechanisms [Mechanism]
	| Caps {ctHash :: BS.ByteString,
		ctNode :: BS.ByteString,
		ctVer :: BS.ByteString } -- [(CapsTag, BS.ByteString)]
	| Rosterver Requirement
	| Bind Requirement
	| Session Requirement
	| FeatureRaw XmlNode
	deriving (Eq, Show)

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

data Mechanism = ScramSha1 | DigestMd5 | MechanismRaw XmlNode deriving (Eq, Show)

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

data IqTag = IqId | IqType | IqTo | IqFrom | IqRaw QName deriving (Eq, Show)

toIqTag :: QName -> IqTag
toIqTag ((_, Just "jabber:client"), "id") = IqId
toIqTag ((_, Just "jabber:client"), "type") = IqType
toIqTag ((_, Just "jabber:client"), "to") = IqTo
toIqTag ((_, Just "jabber:client"), "from") = IqFrom
toIqTag n = IqRaw n

data DiscoTag = DTNode | DTRaw QName deriving (Eq, Show)

toDiscoTag :: QName -> DiscoTag
toDiscoTag ((_, Just "http://jabber.org/protocol/disco#info"), "node") = DTNode
toDiscoTag n = DTRaw n

data IqBody
	= IqBind Bind
	| IqRoster [(RosterTag, BS.ByteString)] -- QueryRoster
	| IqDiscoInfo
	| IqDiscoInfoNode [(DiscoTag, BS.ByteString)]
	| IqDiscoInfoFull [(DiscoTag, BS.ByteString)] Identity [InfoFeature]
	| IqBodyNull
	| IqBodyRaw [XmlNode]
	deriving Show

toIqBody :: [XmlNode] -> IqBody
toIqBody [XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-bind"), "bind") _ [] ns] =
	IqBind $ toBind ns
toIqBody [XmlNode ((_, Just "jabber:iq:roster"), "query") _ as []] =
	IqRoster $ map (first toRosterTag) as
toIqBody [XmlNode ((_, Just "http://jabber.org/protocol/disco#info"), "query")
	_ [] []] = IqDiscoInfo
toIqBody [XmlNode ((_, Just "http://jabber.org/protocol/disco#info"), "query")
	_ as []] = IqDiscoInfoNode $ map (first toDiscoTag) as
toIqBody [XmlNode ((_, Just "http://jabber.org/protocol/disco#info"), "query")
	_ as (i : ns)] = IqDiscoInfoFull
	(map (first toDiscoTag) as)
	(toIdentity i)
	(map toInfoFeature ns)
toIqBody [] = IqBodyNull
toIqBody ns = IqBodyRaw ns

data Identity
	= Identity [(IdentityTag, BS.ByteString)]
	| IdentityRaw XmlNode
	deriving Show

data IdentityTag
	= IDTType | IDTName | IDTCategory | IDTRaw QName deriving (Eq, Show)

toIdentityTag :: QName -> IdentityTag
toIdentityTag ((_, Just "http://jabber.org/protocol/disco#info"), "type") = IDTType
toIdentityTag ((_, Just "http://jabber.org/protocol/disco#info"), "name") = IDTName
toIdentityTag ((_, Just "http://jabber.org/protocol/disco#info"), "category") =
	IDTCategory
toIdentityTag n = IDTRaw n

toIdentity :: XmlNode -> Identity
toIdentity (XmlNode ((_, Just "http://jabber.org/protocol/disco#info"), "identity")
	_ as []) = Identity $ map (first toIdentityTag) as
toIdentity n = IdentityRaw n

data InfoFeature
	= InfoFeature BS.ByteString
	| InfoFeatureSemiRaw [(InfoFeatureTag, BS.ByteString)]
	| InfoFeatureRaw XmlNode
	deriving Show

data InfoFeatureTag
	= IFTVar
	| IFTVarRaw QName
	deriving (Eq, Show)

toInfoFeatureTag :: QName -> InfoFeatureTag
toInfoFeatureTag ((_, Just "http://jabber.org/protocol/disco#info"), "var") = IFTVar
toInfoFeatureTag n = IFTVarRaw n

toInfoFeature :: XmlNode -> InfoFeature
toInfoFeature (XmlNode ((_, Just "http://jabber.org/protocol/disco#info"),
	"feature") _ as []) = case map (first toInfoFeatureTag) as of
		[(IFTVar, v)] -> InfoFeature v
		atts -> InfoFeatureSemiRaw atts
toInfoFeature n = InfoFeatureRaw n

data Bind
	= Jid BS.ByteString
	| BindRaw [XmlNode]
	deriving Show

data RosterTag = RTVer | RTRaw QName deriving (Eq, Show)

toRosterTag :: QName -> RosterTag
toRosterTag ((_, Just "jabber:iq:roster"), "ver") = RTVer
toRosterTag n = RTRaw n

toBind :: [XmlNode] -> Bind
toBind [XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-bind"), "jid") _ []
	[XmlCharData cd]] = Jid cd
toBind ns = BindRaw ns

data Caps
	= C [(CapsTag, BS.ByteString)]
	| CapsRaw [XmlNode]
	deriving Show

toCaps :: [XmlNode] -> Caps
toCaps [XmlNode ((_, Just "http://jabber.org/protocol/caps"), "c") _ as []] =
	C $ map (first toCapsTag) as
toCaps ns = CapsRaw ns

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
showResponse (XmlNode ((_, Just "jabber:client"), "iq") _ as ns) =
	SRIq (map (first toIqTag) as) $ toIqBody ns
showResponse (XmlNode ((_, Just "jabber:client"), "presence") _ as ns) =
	SRPresence (map (first qnameToTag) as) $ toCaps ns
showResponse (XmlNode ((_, Just "jabber:client"), "message") _ as
	(b : d : xd : [])) = SRMessage
		(map (first toIqTag) as)
		(toBody b)
		(toDelay d)
		(toXDelay xd)
showResponse n = SRRaw n

output :: HandleLike h => h -> Pipe XmlNode () (HandleMonad h) ()
output h = do
	mn <- await
	case mn of
		Just n -> lift (hlPut h $ xmlString [n]) >> output h
		_ -> return ()

process :: Monad m => Pipe ShowResponse XmlNode m ()
process = do
	mr <- await
	case mr of
		Just r -> mapM_ yield (mkWriteData r) >> process
		_ -> return ()

mkWriteData :: ShowResponse -> [XmlNode]
mkWriteData (SRFeatures fs)
	| Rosterver Optional `elem` fs = [
		XmlNode (nullQ, "iq") [] [
			((nullQ, "id"), "_xmpp_bind1"),
			((nullQ, "type"), "set") ] [bind],
		iqSession,
		iqRoster,
		XmlNode	(nullQ, "presence") []
			[((nullQ, "id"), "prof_presence_1")]
			[capsToXml profanityCaps "http://www.profanity.im"] ]
mkWriteData (SRChallenge r n q c _a) = let
	dr = DR {	drUserName = sender,
			drRealm = r,
			drPassword = "password",
			drCnonce = "00DEADBEEF00",
			drNonce = n,
			drNc = "00000001",
			drQop = q,
			drDigestUri = "xmpp/localhost",
			drCharset = c }
	ret = kvsToS $ responseToKvs True dr
--	Just sret = lookup "response" $ responseToKvs False dr
	node = (: []) $ XmlNode
		(("", Nothing), "response")
		[("", "urn:ietf:params:xml:ns:xmpp-sasl")] []
		[XmlCharData $ encode ret] in
	node
mkWriteData (SRChallengeRspauth _) = (:[]) $ XmlNode
	(("", Nothing), "response") [("", "urn:ietf:params:xml:ns:xmpp-sasl")] [] []
mkWriteData SRSaslSuccess = begin
mkWriteData (SRPresence _ (C [(CTHash, "sha-1"), (CTVer, v), (CTNode, n)])) =
	(: []) $ XmlNode
		(("", Nothing), "iq") [] [
			((("", Nothing), "id"), "prof_caps_2"),
			((("", Nothing), "to"),
				sender `BS.append` "@localhost/profanity"),
			((("", Nothing), "type"), "get")] [capsQuery v n]
mkWriteData (SRIq [(IqId, i), (IqType, "get"), (IqTo, to), (IqFrom, f)]
	(IqDiscoInfoNode [(DTNode, n)]))
	| to == sender `BS.append` "@localhost/profanity" = [
		XmlNode (("", Nothing), "iq") [] [
				((("", Nothing), "id"), i),
				((("", Nothing), "to"), f),
				((("", Nothing), "type"), "result")]
			[capsToQuery profanityCaps n],
		XmlNode (("", Nothing), "message") [] [
			((("", Nothing), "id"), "prof_3"),
			((("", Nothing), "to"), recipient `BS.append` "@localhost"),
			((("", Nothing), "type"), "chat") ] [message],
		XmlEnd (("stream", Nothing), "stream") ]
mkWriteData _ = []

nullQ :: (BS.ByteString, Maybe BS.ByteString)
nullQ = ("", Nothing)

bind :: XmlNode
bind = XmlNode (nullQ, "bind") [("", "urn:ietf:params:xml:ns:xmpp-bind")] []
	[XmlNode (nullQ, "required") [] [] [], resource]

resource :: XmlNode
resource = XmlNode (nullQ, "resource") [] [] [XmlCharData "profanity"]

session :: XmlNode
session = XmlNode (nullQ, "session")
	[("", "urn:ietf:params:xml:ns:xmpp-session")] [] []

iqSession :: XmlNode
iqSession = XmlNode (nullQ, "iq") []
	[((nullQ, "id"), "_xmpp_session1"), ((nullQ, "type"), "set")] [session]

iqRoster :: XmlNode
iqRoster = XmlNode (nullQ, "iq") []
	[((nullQ, "id"), "roster"), ((nullQ, "type"), "get")] [roster]

roster :: XmlNode
roster = XmlNode (nullQ, "query") [("", "jabber:iq:roster")] [] []

message :: XmlNode
message = XmlNode (("", Nothing), "body") [] [] [XmlCharData "HOGERU"]

capsQuery :: BS.ByteString -> BS.ByteString -> XmlNode
capsQuery v n = XmlNode (("", Nothing), "query")
	[("", "http://jabber.org/protocol/disco#info")]
	[((("", Nothing), "node"), n `BS.append` "#" `BS.append` v)] []

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

-- printP :: (Show a, Monad m, MonadIO m) => Pipe a () m ()
printP :: (Show a, HandleLike h) => h -> Pipe a () (HandleMonad h) ()
printP h = await >>=
	maybe (return ()) (\x -> lift (hlDebug h "critical" $ showBS x) >> printP h)

showBS :: Show a => a -> BS.ByteString
showBS = BSC.pack . (++ "\n") . show

convert :: Monad m => (a -> b) -> Pipe a b m ()
convert f = await >>= maybe (return ()) (\x -> yield (f x) >> convert f)
