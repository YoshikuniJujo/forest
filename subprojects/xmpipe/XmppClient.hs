{-# LANGUAGE OverloadedStrings, TypeFamilies, TupleSections,
	PackageImports, FlexibleContexts #-}

module XmppClient (
	SHandle(..),
	input, output,
	ShowResponse(..),
	IqTag(..),
	IqBody(..),
	DiscoTag(..),
	Caps(..),
	CapsTag(..),
	Tag(..),
	Bind(..),
	Feature(..),
	Mechanism(..),
	Requirement(..),
	MessageXDelay(..),
	MessageDelay(..),
	MessageBody(..),
	InfoFeature(..),
	InfoFeatureTag(..),
	Identity(..),
	IdentityTag(..),
	RosterTag(..),
	DelayTag(..),
	XDelayTag(..),
	voidM,
	MessageType(..),
	Jid(..),
	IqType(..),
	) where

import Control.Arrow
import Control.Monad
import "monads-tf" Control.Monad.State
import Data.Maybe
import Data.Pipe
import Data.HandleLike
import Text.XML.Pipe

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Base64 as B64

import Papillon
import Digest
import Caps (capsToXml, capsToQuery)
import qualified Caps as CAPS

data SHandle s h = SHandle h

instance HandleLike h => HandleLike (SHandle s h) where
	type HandleMonad (SHandle s h) = StateT s (HandleMonad h)
	type DebugLevel (SHandle s h) = DebugLevel h
	hlPut (SHandle h) = lift . hlPut h
	hlGet (SHandle h) = lift . hlGet h
	hlClose (SHandle h) = lift $ hlClose h
	hlDebug (SHandle h) = (lift .) . hlDebug h

input :: HandleLike h => h -> Pipe () ShowResponse (HandleMonad h) ()
input h = handleP h
	=$= xmlEvent
	=$= convert fromJust
	=$= xmlPipe
	=$= checkP h
	=$= convert showResponse
	=$= checkSR h

checkP :: HandleLike h => h -> Pipe XmlNode XmlNode (HandleMonad h) ()
checkP h = do
	mn <- await
	case mn of
		Just n@(XmlStart (_, "stream") _ _) ->
			lift (hlDebug h "critical" $ showBS n) >>
				yield n >> checkP h
		Just n@(XmlNode (_, "challenge") _ _ [XmlCharData cd]) ->
			lift (hlDebug h "critical" . (`BS.append` "\n\n") .
					(\(Right s) -> s) $ B64.decode cd) >>
				yield n >> checkP h
		Just n -> yield n >> checkP h
		_ -> return ()

checkSR :: HandleLike h => h -> Pipe ShowResponse ShowResponse (HandleMonad h) ()
checkSR h = do
	mr <- await
	case mr of
		Just r -> lift (hlDebug h "critical" . (`BS.append` "\n") $
			showBS r) >> yield r >> checkSR h
		_ -> return ()

voidM :: Monad m => m a -> m ()
voidM = (>> return ())

xmlPipe :: Monad m => Pipe XmlEvent XmlNode m ()
xmlPipe = do
	c <- xmlBegin >>= xmlNode
	when c xmlPipe

data ShowResponse
	= SRXmlDecl
	| SRStream [(Tag, BS.ByteString)]
	| SRFeatures [Feature]
	| SRAuth Mechanism
	| SRChallenge {
		realm :: BS.ByteString,
		nonce :: BS.ByteString,
		qop :: BS.ByteString,
		charset :: BS.ByteString,
		algorithm :: BS.ByteString }
	| SRResponse DigestResponse
	| SRResponseNull
	| SRChallengeRspauth BS.ByteString
	| SRSaslSuccess
	| SRIq IqType [(IqTag, BS.ByteString)] IqBody
	| SRPresence [(Tag, BS.ByteString)] Caps
	| SRPresenceRaw BS.ByteString BS.ByteString CAPS.Caps
	| SRMessage [(IqTag, BS.ByteString)] MessageBody MessageDelay MessageXDelay
	| SRMessageRaw MessageType BS.ByteString Jid BS.ByteString
	| SREnd
	| SRRaw XmlNode
	deriving Show

data IqType = Get | Set | Result | ITError deriving (Eq, Show)

data MessageType = Normal | Chat | Groupchat | Headline | MTError
	deriving (Eq, Show)

data Jid = Jid BS.ByteString BS.ByteString (Maybe BS.ByteString) deriving (Eq, Show)

fromJid :: Jid -> BS.ByteString
fromJid (Jid a d r) = a `BS.append` "@" `BS.append` d `BS.append` fromMaybe "" r

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

data Tag = Id | From | To | Version | Lang | TagRaw QName deriving (Eq, Show)

qnameToTag :: QName -> Tag
qnameToTag ((_, Just "jabber:client"), "id") = Id
qnameToTag ((_, Just "jabber:client"), "from") = From
qnameToTag ((_, Just "jabber:client"), "to") = To
qnameToTag ((_, Just "jabber:client"), "version") = Version
qnameToTag (("xml", Nothing), "lang") = Lang
qnameToTag n = TagRaw n

fromTag :: Tag -> QName
fromTag Id = (nullQ, "id")
fromTag From = (nullQ, "from")
fromTag To = (nullQ, "to")
fromTag Version = (nullQ, "version")
fromTag Lang = (("xml", Nothing), "lang")
fromTag (TagRaw n) = n

data CapsTag = CTHash | CTNode | CTVer | CTRaw QName deriving (Eq, Show)

toCapsTag :: QName -> CapsTag
toCapsTag ((_, Just "http://jabber.org/protocol/caps"), "hash") = CTHash
toCapsTag ((_, Just "http://jabber.org/protocol/caps"), "ver") = CTVer
toCapsTag ((_, Just "http://jabber.org/protocol/caps"), "node") = CTNode
toCapsTag n = CTRaw n

-- fromCapsTag :: CapsTag -> QName
-- fromCapsTag

data IqTag = IqId | IqType | IqTo | IqFrom | IqRaw QName deriving (Eq, Show)

toIqTag :: QName -> IqTag
toIqTag ((_, Just "jabber:client"), "id") = IqId
toIqTag ((_, Just "jabber:client"), "type") = IqType
toIqTag ((_, Just "jabber:client"), "to") = IqTo
toIqTag ((_, Just "jabber:client"), "from") = IqFrom
toIqTag n = IqRaw n

fromIqTag :: IqTag -> QName
fromIqTag IqId = (nullQ, "id")
fromIqTag IqType = (nullQ, "type")
fromIqTag IqTo = (nullQ, "to")
fromIqTag IqFrom = (nullQ, "from")
fromIqTag (IqRaw n) = n

data DiscoTag = DTNode | DTRaw QName deriving (Eq, Show)

toDiscoTag :: QName -> DiscoTag
toDiscoTag ((_, Just "http://jabber.org/protocol/disco#info"), "node") = DTNode
toDiscoTag n = DTRaw n

data IqBody
	= IqBind Bind
	| IqSession
	| IqRoster [(RosterTag, BS.ByteString)] -- QueryRoster
	| IqCapsQuery BS.ByteString BS.ByteString
	| IqCapsQuery2 CAPS.Caps BS.ByteString
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

session :: XmlNode
session = XmlNode (nullQ, "session")
	[("", "urn:ietf:params:xml:ns:xmpp-session")] [] []

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
	= BJid BS.ByteString
	| Resource BS.ByteString
	| BindRaw [XmlNode]
	deriving Show

resource :: BS.ByteString -> XmlNode
resource r = XmlNode (nullQ, "resource") [] [] [XmlCharData r]

fromBind :: Bind -> [XmlNode]
fromBind (BJid _) = error "fromBind: not implemented"
fromBind (Resource r) = [
	XmlNode (nullQ, "bind") [("", "urn:ietf:params:xml:ns:xmpp-bind")] []
		[XmlNode (nullQ, "required") [] [] [], resource r]
	]
fromBind (BindRaw ns) = ns

data RosterTag = RTVer | RTRaw QName deriving (Eq, Show)

toRosterTag :: QName -> RosterTag
toRosterTag ((_, Just "jabber:iq:roster"), "ver") = RTVer
toRosterTag n = RTRaw n

toBind :: [XmlNode] -> Bind
toBind [XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-bind"), "jid") _ []
	[XmlCharData cd]] = BJid cd
toBind ns = BindRaw ns

data Caps
	= C [(CapsTag, BS.ByteString)]
	| CapsRaw [XmlNode]
	deriving Show

toCaps :: [XmlNode] -> Caps
toCaps [XmlNode ((_, Just "http://jabber.org/protocol/caps"), "c") _ as []] =
	C $ map (first toCapsTag) as
toCaps ns = CapsRaw ns

-- fromCaps :: Caps -> [XmlNode]
-- fromCaps 
-- fromCaps (CapsRaw ns) = ns

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
	SRIq t ts' $ toIqBody ns
	where
	ts = map (first toIqTag) as
	ts' = filter ((/= IqType) . fst) ts
	Just st = lookup IqType ts
	t = case st of
		"get" -> Get
		"set" -> Set
		"result" -> Result
		"error" -> ITError
		_ -> error "showResonse: bad"
showResponse (XmlNode ((_, Just "jabber:client"), "presence") _ as ns) =
	SRPresence (map (first qnameToTag) as) $ toCaps ns
showResponse (XmlNode ((_, Just "jabber:client"), "message") _ as
	(b : d : xd : [])) = SRMessage
		(map (first toIqTag) as)
		(toBody b)
		(toDelay d)
		(toXDelay xd)
showResponse n = SRRaw n

showResponseToXmlNode :: ShowResponse -> XmlNode
showResponseToXmlNode SRXmlDecl = XmlDecl (1, 0)
showResponseToXmlNode (SRStream as) = XmlStart
	(("stream", Nothing), "stream")
	[	("", "jabber:client"),
		("stream", "http://etherx.jabber.org/streams") ]
	(map (first fromTag) as)
showResponseToXmlNode (SRAuth ScramSha1) = XmlNode (nullQ, "auth")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")]
	[((("", Nothing), "mechanism"), "SCRAM-SHA1")] []
showResponseToXmlNode (SRAuth DigestMd5) = XmlNode (nullQ, "auth")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")]
	[((("", Nothing), "mechanism"), "DIGEST-MD5")] []
showResponseToXmlNode (SRAuth (MechanismRaw n)) = n
showResponseToXmlNode (SRResponse dr) = drToXmlNode dr
showResponseToXmlNode SRResponseNull = drnToXmlNode
showResponseToXmlNode (SRIq it as (IqBind b)) = XmlNode (nullQ, "iq") []
	(t : map (first fromIqTag) as) $ fromBind b
	where
	t = ((nullQ, "type") ,) $ case it of
		Get -> "get"
		Set -> "set"
		Result -> "result"
		ITError -> "error"
showResponseToXmlNode (SRIq it as IqSession) = XmlNode (nullQ, "iq") []
	(t : map (first fromIqTag) as) [session]
	where
	t = ((nullQ, "type") ,) $ case it of
		Get -> "get"
		Set -> "set"
		Result -> "result"
		ITError -> "error"
showResponseToXmlNode (SRIq it as (IqRoster [])) = XmlNode (nullQ, "iq") []
	(t : map (first fromIqTag) as) [roster]
	where
	t = ((nullQ, "type") ,) $ case it of
		Get -> "get"
		Set -> "set"
		Result -> "result"
		ITError -> "error"
showResponseToXmlNode (SRIq it as (IqCapsQuery v n)) = XmlNode (nullQ, "iq") []
	(t : map (first fromIqTag) as) [capsQuery v n]
	where
	t = ((nullQ, "type") ,) $ case it of
		Get -> "get"
		Set -> "set"
		Result -> "result"
		ITError -> "error"
showResponseToXmlNode (SRIq it as (IqCapsQuery2 c n)) = XmlNode (nullQ, "iq") []
	(t : map (first fromIqTag) as) [capsToQuery c n]
	where
	t = ((nullQ, "type") ,) $ case it of
		Get -> "get"
		Set -> "set"
		Result -> "result"
		ITError -> "error"
showResponseToXmlNode (SRPresenceRaw i n c) =
	XmlNode (nullQ, "presence") [] [((nullQ, "id"), i)] [capsToXml c n]
--			[capsToXml profanityCaps "http://www.profanity.im"] ]
showResponseToXmlNode (SRMessageRaw mt i j m) =
	XmlNode (nullQ, "message") []
		[t,((nullQ, "id"), i), ((nullQ, "to"), fromJid j)]
		[XmlNode (nullQ, "body") [] [] [XmlCharData m]]
	where
	t = ((nullQ, "type") ,) $ case mt of
		Normal -> "normal"
		Chat -> "chat"
		_ -> error "showResponseToXmlNode: not implemented yet"
showResponseToXmlNode SREnd = XmlEnd (("stream", Nothing), "stream")
showResponseToXmlNode (SRRaw n) = n
showResponseToXmlNode _ = error "not implemented yet"

output :: HandleLike h => h -> Pipe ShowResponse () (HandleMonad h) ()
output h = do
	mn <- await
	case mn of
		Just n -> lift (hlPut h $
			xmlString [showResponseToXmlNode n]) >> output h
		_ -> return ()

drToXmlNode :: DigestResponse -> XmlNode
drToXmlNode dr = XmlNode (("", Nothing), "response")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")] []
	[XmlCharData . encode . kvsToS $ responseToKvs True dr]

drnToXmlNode :: XmlNode
drnToXmlNode = XmlNode (nullQ, "response")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")] [] []


nullQ :: (BS.ByteString, Maybe BS.ByteString)
nullQ = ("", Nothing)

roster :: XmlNode
roster = XmlNode (nullQ, "query") [("", "jabber:iq:roster")] [] []

capsQuery :: BS.ByteString -> BS.ByteString -> XmlNode
capsQuery v n = XmlNode (("", Nothing), "query")
	[("", "http://jabber.org/protocol/disco#info")]
	[((("", Nothing), "node"), n `BS.append` "#" `BS.append` v)] []

handleP :: HandleLike h => h -> Pipe () BS.ByteString (HandleMonad h) ()
handleP h = do
	c <- lift $ hlGetContent h
	yield c
	handleP h

showBS :: Show a => a -> BS.ByteString
showBS = BSC.pack . (++ "\n") . show

convert :: Monad m => (a -> b) -> Pipe a b m ()
convert f = await >>= maybe (return ()) (\x -> yield (f x) >> convert f)
