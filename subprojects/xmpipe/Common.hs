{-# LANGUAGE OverloadedStrings, TupleSections #-}

module Common (
	toXml,
	showResponse,
	Common(..), Tag(..), Mechanism(..),
	Requirement(..),
	Feature(..), Bind(..), Jid(..), Query(..),
	Roster(..), Identity(..), IdentityTag(..),
	DiscoTag(..), InfoFeature(..), InfoFeatureTag(..),
	IqType(..),
	MessageBody(..),
	MessageDelay(..), DelayTag(..), toDelay,
	MessageXDelay(..), XDelayTag(..), toXDelay,
	MBody(..),
	MessageType(..),
	CapsTag(..), Caps(..),
	nullQ,
	capsToCaps,
	isCaps,
	) where

import Control.Applicative
import Control.Arrow
import Data.List
import Data.Maybe
import Text.XML.Pipe

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Base64 as B64

import qualified Caps as CAPS
import Digest
import Papillon

data Common
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
	| SRResponse BS.ByteString DigestResponse
	| SRChallengeRspauth BS.ByteString
	| SRResponseNull
	| SRSaslSuccess
	| SRIq IqType BS.ByteString (Maybe Jid) (Maybe Jid) Query
	| SRPresence [(Tag, BS.ByteString)] Caps
	| SRMessage MessageType BS.ByteString (Maybe Jid) Jid MBody
	| SREnd
	| SRRaw XmlNode
	deriving Show

data Tag
	= Id | From | To | Version | Lang | Mechanism | Type
	| TagRaw QName
	deriving (Eq, Show)

data Mechanism
	= ScramSha1 | DigestMd5 | Plain | MechanismRaw BS.ByteString
	deriving (Eq, Show)

data Requirement = Optional | Required | NoRequirement [XmlNode]
	deriving (Eq, Show)

data Feature
	= Mechanisms [Mechanism]
	| Caps {
		chash :: BS.ByteString,
		cver :: BS.ByteString,
		cnode :: BS.ByteString }
	| Rosterver Requirement
	| Bind Requirement
	| Session Requirement
	| FeatureRaw XmlNode
	deriving Show

data Bind
	= Resource BS.ByteString
	| BJid Jid
	| BindRaw XmlNode
	deriving Show

data Jid = Jid BS.ByteString BS.ByteString (Maybe BS.ByteString) deriving (Eq, Show)

data Query
	= IqBind (Maybe Requirement) Bind
	| IqSession
	| IqSessionNull
	| IqRoster (Maybe Roster)
	| QueryRaw [XmlNode]

	| IqCapsQuery BS.ByteString BS.ByteString
	| IqCapsQuery2 CAPS.Caps BS.ByteString
	| IqDiscoInfo
	| IqDiscoInfoNode [(DiscoTag, BS.ByteString)]
	| IqDiscoInfoFull [(DiscoTag, BS.ByteString)] Identity [InfoFeature]
	deriving Show

data DiscoTag = DTNode | DTRaw QName deriving (Eq, Show)

toDiscoTag :: QName -> DiscoTag
toDiscoTag ((_, Just "http://jabber.org/protocol/disco#info"), "node") = DTNode
toDiscoTag n = DTRaw n

data Roster
	= Roster (Maybe BS.ByteString) [XmlNode]
	deriving Show

data InfoFeature
	= InfoFeature BS.ByteString
	| InfoFeatureSemiRaw [(InfoFeatureTag, BS.ByteString)]
	| InfoFeatureRaw XmlNode
	deriving Show

toInfoFeature :: XmlNode -> InfoFeature
toInfoFeature (XmlNode ((_, Just "http://jabber.org/protocol/disco#info"),
	"feature") _ as []) = case map (first toInfoFeatureTag) as of
		[(IFTVar, v)] -> InfoFeature v
		atts -> InfoFeatureSemiRaw atts
toInfoFeature n = InfoFeatureRaw n

data InfoFeatureTag
	= IFTVar
	| IFTVarRaw QName
	deriving (Eq, Show)

toInfoFeatureTag :: QName -> InfoFeatureTag
toInfoFeatureTag ((_, Just "http://jabber.org/protocol/disco#info"), "var") = IFTVar
toInfoFeatureTag n = IFTVarRaw n

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

data IqType = Get | Set | Result | ITError deriving (Eq, Show)

data Caps
	= C [(CapsTag, BS.ByteString)]
	| CapsRaw [XmlNode]
	deriving Show

toCaps :: [XmlNode] -> Caps
toCaps [XmlNode ((_, Just "http://jabber.org/protocol/caps"), "c") _ as []] =
	C $ map (first toCapsTag) as
toCaps ns = CapsRaw ns

capsToCaps :: CAPS.Caps -> BS.ByteString -> Caps
capsToCaps c n = C [(CTHash, "sha-1"), (CTNode, n), (CTVer, CAPS.mkHash c)]

fromCaps :: Caps -> [XmlNode]
fromCaps (C ts) = (: []) $ XmlNode (nullQ "c")
	[("", "http://jabber.org/protocol/caps")] (map (first fromCapsTag) ts) []
fromCaps (CapsRaw ns) = ns

data CapsTag = CTHash | CTNode | CTVer | CTRaw QName deriving (Eq, Show)

toCapsTag :: QName -> CapsTag
toCapsTag ((_, Just "http://jabber.org/protocol/caps"), "hash") = CTHash
toCapsTag ((_, Just "http://jabber.org/protocol/caps"), "ver") = CTVer
toCapsTag ((_, Just "http://jabber.org/protocol/caps"), "node") = CTNode
toCapsTag n = CTRaw n

fromCapsTag :: CapsTag -> QName
fromCapsTag CTHash = (nullQ "hash")
fromCapsTag CTVer = (nullQ "ver")
fromCapsTag CTNode = (nullQ "node")
fromCapsTag (CTRaw n) = n

nullQ :: BS.ByteString -> QName
nullQ = (("", Nothing) ,)

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

data MBody
	= MBody MessageBody
	| MBodyDelay MessageBody MessageDelay MessageXDelay
	| MBodyRaw [XmlNode]
	deriving Show

data MessageType = Normal | Chat | Groupchat | Headline | MTError
	deriving (Eq, Show)

toIqBody :: [XmlNode] -> Query
toIqBody [XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-bind"), "bind") _ []
	[n]] = IqBind Nothing $ toBind n
toIqBody [XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-bind"), "bind") _ []
	[n, n']] | r <- toRequirement [n] = IqBind (Just r) $ toBind n'
toIqBody [XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-session"), "session")
	_ [] []] = IqSession
toIqBody [XmlNode ((_, Just "jabber:iq:roster"), "query") _ [] []] =
	IqRoster Nothing
toIqBody [XmlNode ((_, Just "jabber:iq:roster"), "query") _ as ns] = IqRoster
	. Just $ Roster (snd <$> find (\((_, v), _) -> v == "ver") as) ns
toIqBody [XmlNode ((_, Just "http://jabber.org/protocol/disco#info"), "query")
	_ [] []] = IqDiscoInfo
toIqBody [XmlNode ((_, Just "http://jabber.org/protocol/disco#info"), "query")
	_ as []] = IqDiscoInfoNode $ map (first toDiscoTag) as
toIqBody [XmlNode ((_, Just "http://jabber.org/protocol/disco#info"), "query")
	_ as (i : ns)] = IqDiscoInfoFull
	(map (first toDiscoTag) as)
	(toIdentity i)
	(map toInfoFeature ns)
toIqBody [] = IqSessionNull
toIqBody ns = QueryRaw ns

toBind :: XmlNode -> Bind
toBind (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-bind"), "resource") [] []
	[XmlCharData cd]) = Resource cd
toBind n = BindRaw n

fromJid :: Jid -> BS.ByteString
fromJid (Jid a d r) = a `BS.append` "@" `BS.append` d `BS.append`
	maybe "" ("/" `BS.append`) r

toJid :: BS.ByteString -> Jid
toJid j = Jid a d (if BS.null r then Nothing else Just $ BS.tail r)
	where
	(a, rst) = BSC.span (/= '@') j
	(d, r) = BSC.span (/= '/') $ BS.tail rst

toMessageType :: BS.ByteString -> MessageType
toMessageType "normal" = Normal
toMessageType "chat" = Chat
toMessageType _ = error "toMessageType: bad"

isCaps :: Feature -> Bool
isCaps Caps{} = True
isCaps _ = False

toFeature :: XmlNode -> Feature
toFeature (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "mechanisms")
	_ [] ns) = Mechanisms $ map toMechanism ns
toFeature (XmlNode ((_, Just "http://jabber.org/protocol/caps"), "c") _ as []) =
	let h = map (first toCapsTag) as in Caps {
		chash = fromJust $ lookup CTHash h,
		cnode = fromJust $ lookup CTNode h,
		cver = (\(Right r) -> r) . B64.decode . fromJust $ lookup CTVer h }
toFeature (XmlNode ((_, Just "urn:xmpp:features:rosterver"), "ver") _ [] r) =
	Rosterver $ toRequirement r
toFeature (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-bind"), "bind") _ [] r) =
	Bind $ toRequirement r
toFeature (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-session"), "session")
	_ [] r) = Session $ toRequirement r
toFeature n = FeatureRaw n

toRequirement :: [XmlNode] -> Requirement
toRequirement [XmlNode (_, "optional") _ [] []] = Optional
toRequirement [XmlNode (_, "required") _ [] []] = Required
toRequirement n = NoRequirement n

fromRequirement :: Requirement -> XmlNode
fromRequirement Optional = XmlNode (nullQ "optional") [] [] []
fromRequirement Required = XmlNode (nullQ "required") [] [] []
fromRequirement (NoRequirement _) = undefined

toMechanism :: XmlNode -> Mechanism
toMechanism (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "mechanism")
	_ [] [XmlCharData "SCRAM-SHA-1"]) = ScramSha1
toMechanism (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "mechanism")
	_ [] [XmlCharData "DIGEST-MD5"]) = DigestMd5
toMechanism (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "mechanism")
	_ [] [XmlCharData "PLAIN"]) = Plain
toMechanism (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "mechanism")
	_ [] [XmlCharData n]) = MechanismRaw n

toTag :: QName -> Tag
toTag ((_, Just "jabber:client"), "type") = Type
toTag ((_, Just "jabber:client"), "id") = Id
toTag ((_, Just "jabber:client"), "from") = From
toTag ((_, Just "jabber:client"), "to") = To
toTag ((_, Just "jabber:client"), "version") = Version
toTag ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "mechanism") = Mechanism
toTag (("xml", Nothing), "lang") = Lang
toTag n = TagRaw n

fromTag :: Tag -> QName
fromTag Type = nullQ "type"
fromTag Id = nullQ "id"
fromTag From = nullQ "from"
fromTag To = nullQ "to"
fromTag Version = nullQ "version"
fromTag Lang = (("xml", Nothing), "lang")
fromTag Mechanism = nullQ "mechanism"
fromTag (TagRaw n) = n

fromBind :: Bind -> [XmlNode]
fromBind (BJid _) = error "fromBind: not implemented"
fromBind (Resource r) = [
	XmlNode (nullQ "bind") [("", "urn:ietf:params:xml:ns:xmpp-bind")] []
		[XmlNode (nullQ "required") [] [] [], resource r]
	]
fromBind (BindRaw n) = [n]

resource :: BS.ByteString -> XmlNode
resource r = XmlNode (nullQ "resource") [] [] [XmlCharData r]

drToXmlNode :: DigestResponse -> XmlNode
drToXmlNode dr = XmlNode (("", Nothing), "response")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")] []
	[XmlCharData . encode . kvsToS $ responseToKvs True dr]

drnToXmlNode :: XmlNode
drnToXmlNode = XmlNode (nullQ "response")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")] [] []

fromQuery :: Query -> [XmlNode]
fromQuery (IqBind Nothing (BJid j)) =
	[XmlNode (nullQ "jid") [] [] [XmlCharData $ fromJid j]]
fromQuery (IqRoster (Just (Roster mv ns))) = (: []) $
	XmlNode (nullQ "query") [("", "jabber:iq:roster")] as ns
	where as = case mv of
		Just v -> [(nullQ "ver", v)]
		_ -> []
fromQuery (IqBind r b) = maybe id ((:) . fromRequirement) r $ fromBind b
fromQuery IqSession = [session]
fromQuery (IqRoster Nothing) = [roster]
fromQuery (IqCapsQuery v n) = [capsQuery v n]
fromQuery (IqCapsQuery2 c n) = [CAPS.capsToQuery c n]
fromQuery IqSessionNull = []
fromQuery (QueryRaw ns) = ns

fromMessageType :: MessageType -> BS.ByteString
fromMessageType Normal = "normal"
fromMessageType Chat = "chat"
fromMessageType Groupchat = "groupchat"
fromMessageType Headline = "headline"
fromMessageType MTError = "error"

messageTypeToAtt :: MessageType -> (QName, BS.ByteString)
messageTypeToAtt = (nullQ "type" ,) . fromMessageType

fromIqType :: IqType -> BS.ByteString
fromIqType Get = "get"
fromIqType Set = "set"
fromIqType Result = "result"
fromIqType ITError = "error"

toIqType :: BS.ByteString -> IqType
toIqType "get" = Get
toIqType "set" = Set
toIqType "result" = Result
toIqType "error" = ITError
toIqType t = error $ "toIqType: unknown iq type " ++ show t

iqTypeToAtt :: IqType -> (QName, BS.ByteString)
iqTypeToAtt = (nullQ "type" ,) . fromIqType

fromChallenge :: BS.ByteString -> BS.ByteString ->
	BS.ByteString -> BS.ByteString -> BS.ByteString -> [XmlNode]
fromChallenge r u q c a = (: []) . XmlCharData . B64.encode $ BS.concat [
	"realm=", BSC.pack $ show r, ",",
	"nonce=", BSC.pack $ show u, ",",
	"qop=", BSC.pack $ show q, ",",
	"charset=", c, "algorithm=", a ] -- md5-sess" ]

fromFeature :: Feature -> XmlNode
fromFeature (Mechanisms ms) = XmlNode (nullQ "mechanisms")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")] [] $
	map mechanismToXmlNode ms
fromFeature c@Caps{} = XmlNode (nullQ "c")
	[("", "http://jabber.org/protocol/caps")]
	[	(nullQ "hash", chash c),
		(nullQ "ver", cver c),
		(nullQ "node", cnode c) ]
	[]
fromFeature (Rosterver r) = XmlNode (nullQ "ver")
	[("", "urn:xmpp:features:rosterver")] [] [fromRequirement r]
fromFeature (Bind r) = XmlNode (nullQ "bind")
	[("", "urn:ietf:params:xml:ns:xmpp-bind")] [] [fromRequirement r]
fromFeature (Session r) = XmlNode (nullQ "session")
	[("", "urn:ietf:params:xml:ns:xmpp-session")] [] [fromRequirement r]
fromFeature (FeatureRaw n) = n

toMechanism' :: BS.ByteString -> Mechanism
toMechanism' "SCRAM-SHA1" = ScramSha1
toMechanism' "DIGEST-MD5" = DigestMd5
toMechanism' "PLAIN" = Plain
toMechanism' m = MechanismRaw m

fromMechanism :: Mechanism -> BS.ByteString
fromMechanism ScramSha1 = "SCRAM-SHA1"
fromMechanism DigestMd5 = "DIGEST-MD5"
fromMechanism Plain = "PLAIN"
fromMechanism (MechanismRaw m) = m

mechanismToXmlNode :: Mechanism -> XmlNode
mechanismToXmlNode m =
	XmlNode (nullQ "mechanism") [] [] [XmlCharData $ fromMechanism m]

showResponse :: XmlNode -> Common
showResponse (XmlStart ((_, Just "http://etherx.jabber.org/streams"), "stream") _
	as) = SRStream $ map (first toTag) as
showResponse (XmlNode ((_, Just "http://etherx.jabber.org/streams"), "features")
	_ [] nds) = SRFeatures $ map toFeature nds
showResponse (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "auth")
	_ as [])
	| [(Mechanism, m)] <- map (first toTag) as = SRAuth $ toMechanism' m
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
showResponse (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "response")
	_ [] [XmlCharData cd]) = let
		Just a = parseAtts . (\(Right s) -> s) $ B64.decode cd
		in
		SRResponse (fromJust $ lookup "response" a) DR {
			drUserName = fromJust $ lookup "username" a,
			drRealm = fromJust $ lookup "realm" a,
			drPassword = "password",
			drCnonce = fromJust $ lookup "cnonce" a,
			drNonce = fromJust $ lookup "nonce" a,
			drNc = fromJust $ lookup "nc" a,
			drQop = fromJust $ lookup "qop" a,
			drDigestUri = fromJust $ lookup "digest-uri" a,
			drCharset = fromJust $ lookup "charset" a }
showResponse (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "response")
	_ [] []) = SRResponseNull
showResponse (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "success")
	_ [] []) = SRSaslSuccess
showResponse (XmlNode ((_, Just "jabber:client"), "iq") _ as ns) =
	SRIq tp i fr to $ toIqBody ns
	where
	ts = map (first toTag) as
	tp = toIqType . fromJust $ lookup Type ts
	Just i = lookup Id ts
	fr = toJid <$> lookup From ts
	to = toJid <$> lookup To ts
showResponse (XmlNode ((_, Just "jabber:client"), "presence") _ as ns) =
	SRPresence (map (first toTag) as) $ toCaps ns

showResponse (XmlNode ((_, Just "jabber:client"), "message") _ as [b, d, xd])
	| XmlNode ((_, Just "jabber:client"), "body") _ [] _ <- b,
		XmlNode ((_, Just "urn:xmpp:delay"), "delay") _ _ [] <- d,
		XmlNode ((_, Just "jabber:x:delay"), "x") _ _ [] <- xd =
		SRMessage tp i fr to $
			MBodyDelay (toBody b) (toDelay d) (toXDelay xd)
	where
	ts = map (first toTag) as
	tp = toMessageType . fromJust $ lookup Type ts
	i = fromJust $ lookup Id ts
	fr = toJid <$> lookup From ts
	to = toJid . fromJust $ lookup To ts
showResponse (XmlNode ((_, Just "jabber:client"), "message") _ as ns) =
	SRMessage tp i fr to $ MBodyRaw ns
	where
	ts = map (first toTag) as
	tp = toMessageType . fromJust $ lookup Type ts
	i = fromJust $ lookup Id ts
	fr = toJid <$> lookup From ts
	to = toJid . fromJust $ lookup To ts
showResponse n = SRRaw n

capsQuery :: BS.ByteString -> BS.ByteString -> XmlNode
capsQuery v n = XmlNode (("", Nothing), "query")
	[("", "http://jabber.org/protocol/disco#info")]
	[((("", Nothing), "node"), n `BS.append` "#" `BS.append` v)] []

roster :: XmlNode
roster = XmlNode (nullQ "query") [("", "jabber:iq:roster")] [] []

session :: XmlNode
session = XmlNode (nullQ "session")
	[("", "urn:ietf:params:xml:ns:xmpp-session")] [] []

toXml :: Common -> XmlNode
toXml (SRXmlDecl) = XmlDecl (1, 0)
toXml (SRStream as) = XmlStart (("stream", Nothing), "stream")
	[	("", "jabber:client"),
		("stream", "http://etherx.jabber.org/streams") ]
	(map (first fromTag) as)
toXml (SRFeatures fs) = XmlNode
	(("stream", Nothing), "features") [] [] $ map fromFeature fs
toXml (SRAuth ScramSha1) = XmlNode (nullQ "auth")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")]
	[((("", Nothing), "mechanism"), "SCRAM-SHA1")] []
toXml (SRAuth DigestMd5) = XmlNode (nullQ "auth")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")]
	[((("", Nothing), "mechanism"), "DIGEST-MD5")] []
toXml c@SRChallenge{} = XmlNode (nullQ "challenge")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")] [] $ fromChallenge
		(realm c) (nonce c) (qop c) (charset c) (algorithm c)
toXml (SRResponse _ dr) = drToXmlNode dr
toXml (SRChallengeRspauth sret) = XmlNode (nullQ "challenge")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")] [] [XmlCharData sret]
toXml SRResponseNull = drnToXmlNode
toXml SRSaslSuccess =
	XmlNode (nullQ "success") [("", "urn:ietf:params:xml:ns:xmpp-sasl")] [] []
toXml (SRIq tp i fr to q) = XmlNode (nullQ "iq") []
	(catMaybes [
		Just $ iqTypeToAtt tp,
		Just (nullQ "id", i),
		(nullQ "from" ,) . fromJid <$> fr,
		(nullQ "to" ,) . fromJid <$> to ])
	(fromQuery q)
toXml (SRPresence ts c) =
	XmlNode (nullQ "presence") [] (map (first fromTag) ts) (fromCaps c)

toXml (SRMessage tp i fr to (MBody (MessageBody m))) =
	XmlNode (nullQ "message") []
		(catMaybes [
			Just $ messageTypeToAtt tp,
			Just (nullQ "id", i),
			(nullQ "from" ,) . fromJid <$> fr,
			Just (nullQ "to", fromJid to) ])
		[XmlNode (nullQ "body") [] [] [XmlCharData m]]
toXml SREnd = XmlEnd (("stream", Nothing), "stream")
toXml (SRRaw n) = n
toXml _ = error "toXml: not implemented yet"
