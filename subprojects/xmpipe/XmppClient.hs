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
import Data.Pipe
import Data.HandleLike
import Text.XML.Pipe

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Base64 as B64

import Papillon
import Digest
import Caps (capsToQuery)

import Common

data SHandle s h = SHandle h

instance HandleLike h => HandleLike (SHandle s h) where
	type HandleMonad (SHandle s h) = StateT s (HandleMonad h)
	type DebugLevel (SHandle s h) = DebugLevel h
	hlPut (SHandle h) = lift . hlPut h
	hlGet (SHandle h) = lift . hlGet h
	hlClose (SHandle h) = lift $ hlClose h
	hlDebug (SHandle h) = (lift .) . hlDebug h

input :: HandleLike h => h -> Pipe () Common (HandleMonad h) ()
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

checkSR :: HandleLike h => h -> Pipe Common Common (HandleMonad h) ()
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

session :: XmlNode
session = XmlNode (nullQ "session")
	[("", "urn:ietf:params:xml:ns:xmpp-session")] [] []

showResponse :: XmlNode -> Common
showResponse (XmlStart ((_, Just "http://etherx.jabber.org/streams"), "stream")
	_ atts) = SRStream $ map (first toTag) atts
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
	SRIq t i fr to $ toIqBody ns
	where
	ts = map (first toTag) as
	Just st = lookup Type ts
	Just i = lookup Id ts
	fr = toJid <$> lookup From ts
	to = toJid <$> lookup To ts
	t = case st of
		"get" -> Get
		"set" -> Set
		"result" -> Result
		"error" -> ITError
		_ -> error "showResonse: bad"
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

showResponseToXmlNode :: Common -> XmlNode
showResponseToXmlNode (SRXmlDecl) = XmlDecl (1, 0)
showResponseToXmlNode (SRStream as) = XmlStart
	(("stream", Nothing), "stream")
	[	("", "jabber:client"),
		("stream", "http://etherx.jabber.org/streams") ]
	(map (first fromTag) as)
showResponseToXmlNode (SRAuth ScramSha1) = XmlNode (nullQ "auth")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")]
	[((("", Nothing), "mechanism"), "SCRAM-SHA1")] []
showResponseToXmlNode (SRAuth DigestMd5) = XmlNode (nullQ "auth")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")]
	[((("", Nothing), "mechanism"), "DIGEST-MD5")] []
showResponseToXmlNode (SRResponse _ dr) = drToXmlNode dr
showResponseToXmlNode SRResponseNull = drnToXmlNode
showResponseToXmlNode (SRIq it i fr to (IqBind r b)) =
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
showResponseToXmlNode (SRIq it i fr to IqSession) =
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
showResponseToXmlNode (SRIq it i fr to (IqRoster Nothing)) =
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
showResponseToXmlNode (SRIq it i fr to (IqCapsQuery v n)) =
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
showResponseToXmlNode (SRIq it i fr to (IqCapsQuery2 c n)) =
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
showResponseToXmlNode (SRPresence ts c) =
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

output :: HandleLike h => h -> Pipe Common () (HandleMonad h) ()
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
	BS.ByteString -> Pipe Common Common m ()
digestMd5 sender = do
	yield $ SRAuth DigestMd5
	mr <- await
	case mr of
		Just r -> do
			let ret = digestMd5Data sender r
			case ret of
				[SRResponse _ dr] -> lift . put . fromJust .
					lookup "response" $ responseToKvs False dr
				_ -> return ()
			mapM_ yield ret
		Nothing -> error "digestMd5: unexpected end of input"
	mr' <- await
	case mr' of
		Just r'@(SRChallengeRspauth sa) -> do
			sa0 <- lift get
			unless (sa == sa0) $ error "process: bad server"
			mapM_ yield $ digestMd5Data sender r'
		Nothing -> error "digestMd5: unexpected end of input"
		_ -> error "digestMd5: bad response"

digestMd5Data :: BS.ByteString -> Common -> [Common]
digestMd5Data sender (SRChallenge r n q c _a) = [SRResponse h dr]
	where
	Just h = lookup "response" $ responseToKvs True dr
	dr = DR {
		drUserName = sender, drRealm = r, drPassword = "password",
		drCnonce = "00DEADBEEF00", drNonce = n, drNc = "00000001",
		drQop = q, drDigestUri = "xmpp/localhost", drCharset = c }
digestMd5Data _ (SRChallengeRspauth _) = [SRResponseNull]
digestMd5Data _ _ = []
