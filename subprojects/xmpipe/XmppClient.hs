{-# LANGUAGE OverloadedStrings, TypeFamilies, TupleSections,
	PackageImports, FlexibleContexts #-}

module XmppClient (
	MBody(..),
	capsToCaps,
	fromJid,
	toJid,
	Common(..),
	isCaps,
	handleP,
	convert,
	digestMd5,
	SHandle(..),
	input, output,
	ShowResponse(..),
	IqTag(..),
	Query(..),
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

import Control.Applicative
import Control.Arrow
import Control.Monad
import "monads-tf" Control.Monad.State
import Data.Maybe
import Data.List
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

import Common

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
	= SRCommon Common

	| SRMessage MessageType BS.ByteString (Maybe Jid) Jid MBody

	| SREnd
	| SRRaw XmlNode
	deriving Show

data MBody
	= MBody MessageBody
	| MBodyDelay MessageBody MessageDelay MessageXDelay
	| MBodyRaw [XmlNode]
	deriving Show

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

data MessageType = Normal | Chat | Groupchat | Headline | MTError
	deriving (Eq, Show)

toMessageType :: BS.ByteString -> MessageType
toMessageType "normal" = Normal
toMessageType "chat" = Chat
toMessageType _ = error "toMessageType: bad"

fromJid :: Jid -> BS.ByteString
fromJid (Jid a d r) = a `BS.append` "@" `BS.append` d `BS.append`
	maybe "" ("/" `BS.append`) r

toJid :: BS.ByteString -> Jid
toJid j = Jid a d (if BS.null r then Nothing else Just $ BS.tail r)
	where
	(a, rst) = BSC.span (/= '@') j
	(d, r) = BSC.span (/= '/') $ BS.tail rst

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
--	Caps $ map (first toCapsTag) as
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

-- data Tag = Id | From | To | Version | Lang | TagRaw QName deriving (Eq, Show)

qnameToTag :: QName -> Tag
qnameToTag ((_, Just "jabber:client"), "id") = Id
qnameToTag ((_, Just "jabber:client"), "from") = From
qnameToTag ((_, Just "jabber:client"), "to") = To
qnameToTag ((_, Just "jabber:client"), "version") = Version
qnameToTag (("xml", Nothing), "lang") = Lang
qnameToTag n = TagRaw n

fromTag :: Tag -> QName
fromTag Id = (nullQ "id")
fromTag From = (nullQ "from")
fromTag To = (nullQ "to")
fromTag Version = (nullQ "version")
fromTag Lang = (("xml", Nothing), "lang")
fromTag (TagRaw n) = n

data IqTag = IqId | IqType | IqTo | IqFrom | IqRaw QName deriving (Eq, Show)

toIqTag :: QName -> IqTag
toIqTag ((_, Just "jabber:client"), "id") = IqId
toIqTag ((_, Just "jabber:client"), "type") = IqType
toIqTag ((_, Just "jabber:client"), "to") = IqTo
toIqTag ((_, Just "jabber:client"), "from") = IqFrom
toIqTag n = IqRaw n

fromIqTag :: IqTag -> QName
fromIqTag IqId = (nullQ "id")
fromIqTag IqType = (nullQ "type")
fromIqTag IqTo = (nullQ "to")
fromIqTag IqFrom = (nullQ "from")
fromIqTag (IqRaw n) = n

session :: XmlNode
session = XmlNode (nullQ "session")
	[("", "urn:ietf:params:xml:ns:xmpp-session")] [] []

resource :: BS.ByteString -> XmlNode
resource r = XmlNode (nullQ "resource") [] [] [XmlCharData r]

fromBind :: Bind -> [XmlNode]
fromBind (BJid _) = error "fromBind: not implemented"
fromBind (Resource r) = [
	XmlNode (nullQ "bind") [("", "urn:ietf:params:xml:ns:xmpp-bind")] []
		[XmlNode (nullQ "required") [] [] [], resource r]
	]
fromBind (BindRaw n) = [n]

data RosterTag = RTVer | RTRaw QName deriving (Eq, Show)

toRosterTag :: QName -> RosterTag
toRosterTag ((_, Just "jabber:iq:roster"), "ver") = RTVer
toRosterTag n = RTRaw n

toBind :: [XmlNode] -> Bind
toBind [XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-bind"), "jid") _ []
	[XmlCharData cd]] = BJid $ toJid cd
toBind [n] = BindRaw n
toBind _ = error "toBind: bad"

showResponse :: XmlNode -> ShowResponse
showResponse (XmlStart ((_, Just "http://etherx.jabber.org/streams"), "stream")
	_ atts) = SRCommon . SRStream $ map (first qnameToTag) atts
showResponse (XmlNode ((_, Just "http://etherx.jabber.org/streams"), "features")
	_ [] nds) = SRCommon . SRFeatures $ map toFeature nds
showResponse (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "challenge")
	_ [] [XmlCharData c]) = let
		Right d = B64.decode c
		Just a = parseAtts d in
		case a of
			[("rspauth", ra)] -> SRCommon $ SRChallengeRspauth ra
			_ -> SRCommon SRChallenge {
				realm = fromJust $ lookup "realm" a,
				nonce = fromJust $ lookup "nonce" a,
				qop = fromJust $ lookup "qop" a,
				charset = fromJust $ lookup "charset" a,
				algorithm = fromJust $ lookup "algorithm" a }
showResponse (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "success")
	_ [] []) = SRCommon SRSaslSuccess
showResponse (XmlNode ((_, Just "jabber:client"), "iq") _ as ns) =
	SRCommon . SRIq t i fr to $ toIqBody ns
	where
	ts = map (first toIqTag) as
	Just st = lookup IqType ts
	Just i = lookup IqId ts
	fr = toJid <$> lookup IqFrom ts
	to = toJid <$> lookup IqTo ts
	t = case st of
		"get" -> Get
		"set" -> Set
		"result" -> Result
		"error" -> ITError
		_ -> error "showResonse: bad"
showResponse (XmlNode ((_, Just "jabber:client"), "presence") _ as ns) =
	SRCommon . SRPresence (map (first qnameToTag) as) $ toCaps ns
showResponse (XmlNode ((_, Just "jabber:client"), "message") _ as [b, d, xd])
	| XmlNode ((_, Just "jabber:client"), "body") _ [] _ <- b,
		XmlNode ((_, Just "urn:xmpp:delay"), "delay") _ _ [] <- d,
		XmlNode ((_, Just "jabber:x:delay"), "x") _ _ [] <- xd =
		SRMessage tp i fr to $
			MBodyDelay (toBody b) (toDelay d) (toXDelay xd)
	where
	ts = map (first toIqTag) as
	tp = toMessageType . fromJust $ lookup IqType ts
	i = fromJust $ lookup IqId ts
	fr = toJid <$> lookup IqFrom ts
	to = toJid . fromJust $ lookup IqTo ts
showResponse (XmlNode ((_, Just "jabber:client"), "message") _ as ns) =
	SRMessage tp i fr to $ MBodyRaw ns
	where
	ts = map (first toIqTag) as
	tp = toMessageType . fromJust $ lookup IqType ts
	i = fromJust $ lookup IqId ts
	fr = toJid <$> lookup IqFrom ts
	to = toJid . fromJust $ lookup IqTo ts
showResponse n = SRRaw n

showResponseToXmlNode :: ShowResponse -> XmlNode
showResponseToXmlNode (SRCommon SRXmlDecl) = XmlDecl (1, 0)
showResponseToXmlNode (SRCommon (SRStream as)) = XmlStart
	(("stream", Nothing), "stream")
	[	("", "jabber:client"),
		("stream", "http://etherx.jabber.org/streams") ]
	(map (first fromTag) as)
showResponseToXmlNode (SRCommon (SRAuth ScramSha1)) = XmlNode (nullQ "auth")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")]
	[((("", Nothing), "mechanism"), "SCRAM-SHA1")] []
showResponseToXmlNode (SRCommon (SRAuth DigestMd5)) = XmlNode (nullQ "auth")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")]
	[((("", Nothing), "mechanism"), "DIGEST-MD5")] []
-- showResponseToXmlNode (SRAuth (MechanismRaw n)) = n
showResponseToXmlNode (SRCommon (SRResponse _ dr)) = drToXmlNode dr
showResponseToXmlNode (SRCommon SRResponseNull) = drnToXmlNode
showResponseToXmlNode (SRCommon (SRIq it i fr to (IqBind r b))) =
	XmlNode (nullQ "iq") [] as .
		(maybe id ((:) . fromRequirement) r) $ fromBind b
	where
	as = catMaybes [
		Just t,
		Just (nullQ "id", i),
		(nullQ "from" ,) . fromJid <$> fr,
		(nullQ "to" ,) . fromJid <$> to ]
	t = (nullQ "type" ,) $ case it of
		Get -> "get"
		Set -> "set"
		Result -> "result"
		ITError -> "error"
showResponseToXmlNode (SRCommon (SRIq it i fr to IqSession)) =
	XmlNode (nullQ "iq") [] as [session]
	where
	as = catMaybes [
		Just t,
		Just ((nullQ "id"), i),
		((nullQ "from") ,) . fromJid <$> fr,
		((nullQ "to") ,) . fromJid <$> to ]
	t = ((nullQ "type") ,) $ case it of
		Get -> "get"
		Set -> "set"
		Result -> "result"
		ITError -> "error"
showResponseToXmlNode (SRCommon (SRIq it i fr to (IqRoster Nothing))) =
	XmlNode (nullQ "iq") [] as [roster]
	where
	as = catMaybes [
		Just t,
		Just ((nullQ "id"), i),
		(nullQ "from" ,) . fromJid <$> fr,
		(nullQ "to" ,) . fromJid <$> to ]
	t = (nullQ "type" ,) $ case it of
		Get -> "get"
		Set -> "set"
		Result -> "result"
		ITError -> "error"
showResponseToXmlNode (SRCommon (SRIq it i fr to (IqCapsQuery v n))) =
	XmlNode (nullQ "iq") [] as [capsQuery v n]
	where
	as = catMaybes [
		Just t,
		Just (nullQ "id", i),
		(nullQ "from" ,) . fromJid <$> fr,
		(nullQ "to" ,) . fromJid <$> to ]
	t = (nullQ "type" ,) $ case it of
		Get -> "get"
		Set -> "set"
		Result -> "result"
		ITError -> "error"
showResponseToXmlNode (SRCommon (SRIq it i fr to (IqCapsQuery2 c n))) =
	XmlNode (nullQ "iq") [] as [capsToQuery c n]
	where
	as = catMaybes [
		Just t,
		Just (nullQ "id", i),
		(nullQ "from" ,) . fromJid <$> fr,
		(nullQ "to" ,) . fromJid <$> to ]
	t = (nullQ "type" ,) $ case it of
		Get -> "get"
		Set -> "set"
		Result -> "result"
		ITError -> "error"
showResponseToXmlNode (SRCommon (SRPresence ts c)) =
	XmlNode (nullQ "presence") [] (map (first fromTag) ts) (fromCaps c)
showResponseToXmlNode (SRMessage mt i Nothing j (MBody (MessageBody m))) =
	XmlNode (nullQ "message") []
		[t,(nullQ "id", i), (nullQ "to", fromJid j)]
		[XmlNode (nullQ "body") [] [] [XmlCharData m]]
	where
	t = (nullQ "type" ,) $ case mt of
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
		Just n -> do
			lift (hlPut h $ xmlString [showResponseToXmlNode n])
			case n of
				SREnd -> lift $ hlClose h
				_ -> return ()
			output h
		_ -> return ()

drToXmlNode :: DigestResponse -> XmlNode
drToXmlNode dr = XmlNode (("", Nothing), "response")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")] []
	[XmlCharData . encode . kvsToS $ responseToKvs True dr]

drnToXmlNode :: XmlNode
drnToXmlNode = XmlNode (nullQ "response")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")] [] []


roster :: XmlNode
roster = XmlNode (nullQ "query") [("", "jabber:iq:roster")] [] []

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

digestMd5 :: (Monad m, MonadState m, StateType m ~ BS.ByteString) =>
	BS.ByteString -> Pipe ShowResponse ShowResponse m ()
digestMd5 sender = do
	yield . SRCommon $ SRAuth DigestMd5
	mr <- await
	case mr of
		Just r -> do
			let ret = digestMd5Data sender r
			case ret of
				[SRCommon (SRResponse _ dr)] -> lift . put . fromJust .
					lookup "response" $ responseToKvs False dr
				_ -> return ()
			mapM_ yield ret
		Nothing -> error "digestMd5: unexpected end of input"
	mr' <- await
	case mr' of
		Just r'@(SRCommon (SRChallengeRspauth sa)) -> do
			sa0 <- lift get
			unless (sa == sa0) $ error "process: bad server"
			mapM_ yield $ digestMd5Data sender r'
		Nothing -> error "digestMd5: unexpected end of input"
		_ -> error "digestMd5: bad response"

digestMd5Data :: BS.ByteString -> ShowResponse -> [ShowResponse]
digestMd5Data sender (SRCommon (SRChallenge r n q c _a)) = [SRCommon (SRResponse h dr)]
	where
	Just h = lookup "response" $ responseToKvs True dr
	dr = DR {
		drUserName = sender, drRealm = r, drPassword = "password",
		drCnonce = "00DEADBEEF00", drNonce = n, drNc = "00000001",
		drQop = q, drDigestUri = "xmpp/localhost", drCharset = c }
digestMd5Data _ (SRCommon (SRChallengeRspauth _)) = [SRCommon SRResponseNull]
digestMd5Data _ _ = []
