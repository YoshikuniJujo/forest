{-# LANGUAGE OverloadedStrings, TupleSections #-}

module Common (
	Common(..), Tag(..), Mechanism(..), Requirement(..),
	Feature(..), Bind(..), Jid(..), Query(..),
	Roster(..), Identity(..), IdentityTag(..),
	DiscoTag(..), InfoFeature(..), InfoFeatureTag(..),
	toDiscoTag, toIdentity, toInfoFeature,
	IqType(..),
	nullQ,
	fromCaps, toCaps, CapsTag(..), Caps(..), toCapsTag, capsToCaps,
	MessageBody(..), toBody,
	MessageDelay(..), DelayTag(..), toDelay,
	MessageXDelay(..), XDelayTag(..), toXDelay,
	MBody(..),
	MessageType(..),
	fromJid, toJid, toBind, toIqBody,
	toMessageType, isCaps, toFeature,
	fromRequirement,
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
toIqBody [XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-bind"), "bind") _ [] ns] =
	IqBind Nothing $ toBind ns
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

toBind :: [XmlNode] -> Bind
toBind [XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-bind"), "jid") _ []
	[XmlCharData cd]] = BJid $ toJid cd
toBind [n] = BindRaw n
toBind _ = error "toBind: bad"

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
