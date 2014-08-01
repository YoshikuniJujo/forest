{-# LANGUAGE OverloadedStrings, TypeFamilies, TupleSections, FlexibleContexts,
	PackageImports #-}

module XmppServer (
	Common(..),
	convert,
	nullQ,
	handleP,
	checkP,
	digestMd5,
	ShowResponse(..), showResponse, toXml,
	Jid(..),
	MessageType(..), messageTypeToAtt, IqType(..), iqTypeToAtt,
	Query(..),
	Iq(..), toIq,
	Tag(..),
	Bind(..),
	Requirement(..),
	Mechanism(..), mechanismToXmlNode,
	Feature(..),
	XmppState(..), initXmppState,
		setReceiver, setResource, nextUuid,
	input,
	output,
	) where

import Data.UUID

import Control.Applicative
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

import DigestSv
import Papillon

import Common

data SHandle s h = SHandle h

instance HandleLike h => HandleLike (SHandle s h) where
	type HandleMonad (SHandle s h) = StateT s (HandleMonad h)
	type DebugLevel (SHandle s h) = DebugLevel h
	hlPut (SHandle h) = lift . hlPut h
	hlGet (SHandle h) = lift . hlGet h
	hlClose (SHandle h) = lift $ hlClose h
	hlDebug (SHandle h) = (lift .) . hlDebug h

data XmppState = XmppState {
	receiver :: Maybe Jid,
	uuidList :: [UUID] }

initXmppState :: [UUID] -> XmppState
initXmppState uuids = XmppState {
	receiver = Nothing,
	uuidList = uuids }

setReceiver :: Jid -> XmppState -> XmppState
setReceiver j xs = xs { receiver = Just j }

setResource :: BS.ByteString -> XmppState -> XmppState
setResource r xs@XmppState{ receiver = Just (Jid a d _) } =
	xs { receiver = Just . Jid a d $ Just r }
setResource _ _ = error "setResource: can't set resource to Nothing"

nextUuid :: (MonadState m, StateType m ~ XmppState) => m UUID
nextUuid = do
	xs@XmppState { uuidList = u : us } <- get
	put xs { uuidList = us }
	return u

output :: (MonadState (HandleMonad h), StateType (HandleMonad h) ~ XmppState,
	HandleLike h) => h -> Pipe ShowResponse () (HandleMonad h) ()
output h = convert toXml =$= outputXml h

input :: HandleLike h => h -> Pipe () ShowResponse (HandleMonad h) ()
input h = handleP h
	=$= xmlEvent
--	=$= checkP h
	=$= convert fromJust
	=$= xmlPipe
	=$= convert showResponse
	=$= checkP h

xmlPipe :: Monad m => Pipe XmlEvent XmlNode m ()
xmlPipe = xmlBegin >>= xmlNode >>= flip when xmlPipe

data ShowResponse
	= SRCommon Common
	| SRResponseNull
	| SRSuccess
	| SRIq [(Tag, BS.ByteString)] [Iq]
	| SRIqRaw IqType BS.ByteString (Maybe Jid) (Maybe Jid) Query
	| SRPresence [(Tag, BS.ByteString)] [XmlNode]
	| SRMessage MessageType BS.ByteString Jid Jid [XmlNode]
	| SRRaw XmlNode
	deriving Show

{-
data Challenge
	= Challenge {
		realm :: BS.ByteString,
		nonce :: UUID }
	| ChallengeRaw [XmlNode]
	deriving Show
	-}

data Query
	= JidResult Jid
	| RosterResult BS.ByteString [XmlNode]
	| QueryNull
	| QueryRaw [XmlNode]
	deriving Show

fromQuery :: Query -> [XmlNode]
fromQuery (JidResult j) = [XmlNode (nullQ "jid") [] [] [XmlCharData $ fromJid j]]
fromQuery (RosterResult v ns) =
	[XmlNode (nullQ "query") [("", "jabber:iq:roster")] [(nullQ "ver", v)] ns]
fromQuery QueryNull = []
fromQuery (QueryRaw ns) = ns

data MessageType
	= Normal | Chat | Groupchat | Headline | MTError deriving (Eq, Show)

fromMessageType :: MessageType -> BS.ByteString
fromMessageType Normal = "normal"
fromMessageType Chat = "chat"
fromMessageType Groupchat = "groupchat"
fromMessageType Headline = "headline"
fromMessageType MTError = "error"

messageTypeToAtt :: MessageType -> (QName, BS.ByteString)
messageTypeToAtt = (nullQ "type" ,) . fromMessageType

data IqType = Get | Set | Result | ITError deriving (Eq, Show)

fromIqType :: IqType -> BS.ByteString
fromIqType Get = "get"
fromIqType Set = "set"
fromIqType Result = "result"
fromIqType ITError = "error"

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

toMechanism :: BS.ByteString -> Mechanism
toMechanism "SCRAM-SHA1" = ScramSha1
toMechanism "DIGEST-MD5" = DigestMd5
toMechanism "PLAIN" = Plain
toMechanism m = MechanismRaw m

fromMechanism :: Mechanism -> BS.ByteString
fromMechanism ScramSha1 = "SCRAM-SHA1"
fromMechanism DigestMd5 = "DIGEST-MD5"
fromMechanism Plain = "PLAIN"
fromMechanism (MechanismRaw m) = m

mechanismToXmlNode :: Mechanism -> XmlNode
mechanismToXmlNode m =
	XmlNode (nullQ "mechanism") [] [] [XmlCharData $ fromMechanism m]

data Iq	= IqBind [XmlNode]
	| IqBindReq Requirement Bind
	| IqSession
	| IqRoster
	| IqRaw XmlNode
	deriving Show

toIq :: XmlNode -> Iq
toIq (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-bind"), "bind") _ [] [n, n'])
	| Just r <- toRequirement n = IqBindReq r $ toBind n'
toIq (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-session"), "session") _ [] [])
	= IqSession
toIq (XmlNode ((_, Just "jabber:iq:roster"), "query") _ [] []) = IqRoster
toIq n = IqRaw n

toRequirement :: XmlNode -> Maybe Requirement
toRequirement (XmlNode (_, "optional") _ [] []) = Just Optional
toRequirement (XmlNode (_, "required") _ [] []) = Just Required
toRequirement _ = Nothing

fromRequirement :: Requirement -> XmlNode
fromRequirement Optional = XmlNode (nullQ "optional") [] [] []
fromRequirement Required = XmlNode (nullQ "required") [] [] []

data Bind
	= Resource BS.ByteString
	| BindRaw XmlNode
	deriving Show

toBind :: XmlNode -> Bind
toBind (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-bind"), "resource") [] []
	[XmlCharData cd]) = Resource cd
toBind n = BindRaw n

showResponse :: XmlNode -> ShowResponse
showResponse (XmlStart ((_, Just "http://etherx.jabber.org/streams"), "stream") _
	as) = SRCommon . SRStream $ map (first toTag) as
showResponse (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "auth")
	_ as [])
	| [(Mechanism, m)] <- map (first toTag) as =
		SRCommon . SRAuth $ toMechanism m
showResponse (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "response")
	_ [] []) = SRResponseNull
showResponse (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "response")
	_ [] [XmlCharData cd]) = let
		Just a = parseAtts . (\(Right s) -> s) $ B64.decode cd
		in
		SRCommon $ SRResponse (fromJust $ lookup "response" a) DR {
			drUserName = fromJust $ lookup "username" a,
			drRealm = fromJust $ lookup "realm" a,
			drPassword = "password",
			drCnonce = fromJust $ lookup "cnonce" a,
			drNonce = fromJust $ lookup "nonce" a,
			drNc = fromJust $ lookup "nc" a,
			drQop = fromJust $ lookup "qop" a,
			drDigestUri = fromJust $ lookup "digest-uri" a,
			drCharset = fromJust $ lookup "charset" a }
showResponse (XmlNode ((_, Just "jabber:client"), "iq")
	_ as ns) = SRIq (map (first toTag) as) (map toIq ns)
showResponse (XmlNode ((_, Just "jabber:client"), "presence")
	_ as ns) = SRPresence (map (first toTag) as) ns
showResponse n = SRRaw n

toTag :: QName -> Tag
toTag ((_, Just "jabber:client"), "to") = To
toTag (("xml", Nothing), "lang") = Lang
toTag ((_, Just "jabber:client"), "version") = Version
toTag ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "mechanism") = Mechanism
toTag ((_, Just "jabber:client"), "id") = Id
toTag ((_, Just "jabber:client"), "type") = Type
toTag n = TagRaw n

fromTag :: Tag -> QName
fromTag Id = nullQ "id"
fromTag From = nullQ "from"
fromTag To = nullQ "to"
fromTag Version = nullQ "version"
fromTag Lang = (("xml", Nothing), "lang")
fromTag Mechanism = nullQ "mechanism"
fromTag Type = nullQ "type"
fromTag (TagRaw n) = n

toXml :: ShowResponse -> XmlNode
toXml (SRCommon SRXmlDecl) = XmlDecl (1, 0)
toXml (SRCommon (SRStream as)) = XmlStart (("stream", Nothing), "stream")
	[	("", "jabber:client"),
		("stream", "http://etherx.jabber.org/streams") ]
	(map (first fromTag) as)
toXml (SRCommon (SRFeatures fs)) = XmlNode
	(("stream", Nothing), "features") [] [] $ map fromFeature fs
toXml (SRCommon c@SRChallenge{}) = XmlNode (nullQ "challenge")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")] [] $ fromChallenge
		(realm c) (nonce c) (qop c) (charset c) (algorithm c)
toXml (SRCommon (SRChallengeRspauth sret)) = XmlNode (nullQ "challenge")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")] [] [XmlCharData sret]
toXml SRSuccess =
	XmlNode (nullQ "success") [("", "urn:ietf:params:xml:ns:xmpp-sasl")] [] []
toXml (SRIqRaw tp i Nothing to q) = XmlNode (nullQ "iq") []
	(catMaybes [
		Just (nullQ "id", i),
		Just $ iqTypeToAtt tp,
		(nullQ "to" ,) . fromJid <$> to ]) 
	(fromQuery q)
toXml (SRMessage tp i fr to ns) = XmlNode (nullQ "message") [] [
	messageTypeToAtt tp,
	(nullQ "from", fromJid fr),
	(nullQ "to", fromJid to),
	(nullQ "id", i) ] ns
toXml (SRRaw n) = n
toXml _ = error "toXml: not implemented"

data Jid = Jid BS.ByteString BS.ByteString (Maybe BS.ByteString) deriving (Eq, Show)

fromJid :: Jid -> BS.ByteString
fromJid (Jid a d r) = BS.concat [a, "@", d] `BS.append` maybe "" ("/" `BS.append`) r

{-
caps :: Feature
caps = Caps {
	chash = "sha-1",
	cver = "k07nuHawZqmndRtf3ZfBm54FwL0=",
	cnode = "http://prosody.im" }
	-}

outputXml :: (MonadState (HandleMonad h), StateType (HandleMonad h) ~ XmppState,
		HandleLike h) => h -> Pipe XmlNode () (HandleMonad h) ()
outputXml h = do
	mx <- await
	case mx of
		Just x -> lift (hlPut h $ xmlString [x]) >> outputXml h
		_ -> return ()

handleP :: HandleLike h => h -> Pipe () BS.ByteString (HandleMonad h) ()
handleP h = do
	c <- lift $ hlGetContent h
	yield c
	handleP h

checkP :: (HandleLike h, Show a) => h -> Pipe a a (HandleMonad h) ()
checkP h = do
	mx <- await
	case mx of
		Just x -> do
			lift . hlDebug h "critical" . BSC.pack . (++ "\n") $ show x
			yield x
			checkP h
		_ -> return ()

nullQ :: BS.ByteString -> QName
nullQ = (("", Nothing) ,)

convert :: Monad m => (a -> b) -> Pipe a b m ()
convert f = await >>= maybe (return ()) (\x -> yield (f x) >> convert f)

digestMd5 :: (MonadState m, StateType m ~ XmppState) =>
	UUID -> Pipe ShowResponse ShowResponse m BS.ByteString
digestMd5 u = do
	yield . SRCommon $ SRFeatures [Mechanisms [DigestMd5]]
	Just (SRCommon (SRAuth DigestMd5)) <- await
	yield . SRCommon $ SRChallenge {
		realm = "localhost",
		nonce = toASCIIBytes u,
		qop = "auth",
		charset = "utf-8",
		algorithm = "md5-sess" }
	Just (SRCommon (SRResponse r dr@DR { drUserName = un })) <- await
	let cret = fromJust . lookup "response" $ responseToKvs True dr
	unless (r == cret) $ error "digestMd5: bad authentication"
	let sret = B64.encode . ("rspauth=" `BS.append`) . fromJust
		. lookup "response" $ responseToKvs False dr
	yield . SRCommon $ SRChallengeRspauth sret
	Just SRResponseNull <- await
	yield SRSuccess
	return un
