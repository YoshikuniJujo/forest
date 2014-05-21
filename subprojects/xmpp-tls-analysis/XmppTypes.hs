{-# LANGUAGE OverloadedStrings, TupleSections #-}

module XmppTypes (
	elementToStanza,
	stanzaToElement,
	Stanza(..),
	Mechanism(..),
	Challenge(..),
	Response(..),
	Feature(..),
	Bind(..),
	IqType(..),
	IqBody(..),
) where

import Control.Applicative
import Data.Maybe
import Data.List
import Data.XML.Types
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Base64 as B64

import DigestMd5

data Stanza
	= StanzaMechanismList [Mechanism]
	| StanzaMechanism Mechanism
	| StanzaChallenge Challenge
	| StanzaResponse Response
	| StanzaSuccess
	| StanzaFeatureList [Feature]
	| StanzaIq {
		iqId :: Text,
		iqType :: IqType,
		iqTo :: Maybe Text,
		iqBody :: IqBody }
	| StanzaPresence {
		presenceId :: Text,
		presenceBody :: [PresenceBody] }
	| StanzaMessage { -- [(Name, [Content])] [Node] -- {
		messageType :: Text, -- MessageType,
		messageId :: Text,
		messageFrom :: Maybe Text,
		messageTo :: Maybe Text,
		messageBody :: [Node] }
	| StanzaTag Tag Element
	| StanzaRaw Element
	deriving Show

data PresenceBody
	= PresenceBodyCaps Caps
	| PresenceBodyRaw Element
	deriving Show

toPresenceBody :: Element -> PresenceBody
toPresenceBody (Element nm ats [])
	| Just TagC <- nameToTag nm = PresenceBodyCaps $ toCaps ats
toPresenceBody e = PresenceBodyRaw e

fromPresenceBody :: PresenceBody -> Element
fromPresenceBody (PresenceBodyCaps c) = Element
	(fromJust $ lookup TagC tagName) (fromCaps c) []
fromPresenceBody (PresenceBodyRaw e) = e

data IqType
	= IqGet
	| IqSet
	| IqResult
	| IqError
	| IqRaw Text
	deriving Show

toIqType :: Text -> IqType
toIqType "get" = IqGet
toIqType "set" = IqSet
toIqType "result" = IqResult
toIqType "error" = IqError
toIqType tp = IqRaw tp

fromIqType :: IqType -> Text
fromIqType IqGet = "get"
fromIqType IqSet = "set"
fromIqType IqResult = "result"
fromIqType IqError = "error"
fromIqType (IqRaw t) = t

data IqBody
	= IqBodyBind [Bind]
	| IqBodySession
	| IqBodyRosterQuery {
		rosterVer :: Maybe Int,
		rosterBody :: [Node] }
	| IqBodyDiscoQuery
	| IqBodyTag Tag Element
	| IqBodyRaw Element
	| IqBodyNull
	deriving Show

toIqBody :: Element -> IqBody
toIqBody (Element nm [] nds)
	| Just TagBind <- nameToTag nm = IqBodyBind $
		map (toBind . \(NodeElement e) -> e) nds
toIqBody (Element nm [] [])
	| Just TagSession <- nameToTag nm = IqBodySession
toIqBody (Element nm ats nds)
	| Just TagRosterQuery <- nameToTag nm = IqBodyRosterQuery {
		rosterVer = read . Text.unpack <$> lookupAttrM "ver" ats,
		rosterBody = nds }
toIqBody (Element nm [] [])
	| Just TagDiscoQuery <- nameToTag nm = IqBodyDiscoQuery
toIqBody e@(Element nm _ _)
	| Just t <- nameToTag nm = IqBodyTag t e
toIqBody e = IqBodyRaw e

fromIqBody :: IqBody -> Element
fromIqBody (IqBodyBind nds) = Element (fromJust $ lookup TagBind tagName) [] $
	map (NodeElement . fromBind) nds
fromIqBody IqBodySession = Element (fromJust $ lookup TagSession tagName) [] []
fromIqBody (IqBodyRosterQuery vr bd) =
	flip (Element . fromJust $ lookup TagRosterQuery tagName) bd $
		maybe [] (\v -> [(Name "ver" Nothing Nothing,
			[ContentText . Text.pack $ show v])]) vr
fromIqBody IqBodyDiscoQuery = Element
	(fromJust $ lookup TagDiscoQuery tagName) [] []
fromIqBody (IqBodyTag _ e) = e
fromIqBody (IqBodyRaw e) = e
fromIqBody IqBodyNull = error "fromIqBody: No iq body"

data Bind
	= Required
	| BindResource Text
	| BindJid Text
	| BindTag Tag Element
	| BindRaw Element
	deriving (Show, Eq)

toBind :: Element -> Bind
toBind (Element nm [] [])
	| Just TagRequired <- nameToTag nm = Required
toBind (Element nm [] [NodeContent (ContentText rn)])
	| Just TagResource <- nameToTag nm = BindResource rn
toBind (Element nm [] [NodeContent (ContentText jid)])
	| Just TagJid <- nameToTag nm = BindJid jid
toBind e@(Element nm _ _)
	| Just t <- nameToTag nm = BindTag t e
toBind e = BindRaw e

fromBind :: Bind -> Element
fromBind Required = Element (fromJust $ lookup TagRequired tagName) [] []
fromBind (BindResource rn) = Element (fromJust $ lookup TagResource tagName) []
	[NodeContent (ContentText rn)]
fromBind (BindJid jid) = Element (fromJust $ lookup TagJid tagName) []
	[NodeContent (ContentText jid)]
fromBind (BindTag _ e) = e
fromBind (BindRaw e) = e

data Feature
	= FeatureVer Ver
	| FeatureBind Bind
	| FeatureSession Session
	| FeatureC Caps
	| FeatureTag Tag Element
	| FeatureRaw Element
	deriving (Show, Eq)

data Caps = Caps {
	capsHash :: Text,
	capsVer :: Text,
	capsNode :: Text } deriving (Show, Eq)

toCaps :: [(Name, [Content])] -> Caps
toCaps ats = Caps {
	capsHash = lookupAttr "hash" ats,
	capsVer = lookupAttr "ver" ats,
	capsNode = lookupAttr "node" ats
 }

fromCaps :: Caps -> [(Name, [Content])]
fromCaps ats = [
	(Name "hash" Nothing Nothing, [ContentText $ capsHash ats]),
	(Name "ver" Nothing Nothing, [ContentText $ capsVer ats]),
	(Name "node" Nothing Nothing, [ContentText $ capsNode ats])
 ]

data Ver
	= Optional
	| VerRaw Element
	deriving (Show, Eq)

data Session
	= SessionOptional
	| SessionRaw Element
	deriving (Show, Eq)

toFeature :: Element -> Feature
toFeature (Element nm [] [NodeElement e])
	| Just TagVer <- nameToTag nm = FeatureVer $ case e of
		Element n [] [] | Just TagOptional <- nameToTag n -> Optional
		_ -> VerRaw e
toFeature (Element nm [] [NodeElement e])
	| Just TagBind <- nameToTag nm = FeatureBind $ case e of
		Element n [] []
			| Just TagRequired <- nameToTag n -> Required
		_ -> BindRaw e
toFeature (Element nm [] [NodeElement e])
	| Just TagSession <- nameToTag nm = FeatureSession $ case e of
		Element n [] []
			| Just TagSessionOptional <- nameToTag n -> SessionOptional
		_ -> SessionRaw e
toFeature (Element nm ats [])
	| Just TagC <- nameToTag nm = FeatureC $ toCaps ats
toFeature e@(Element nm _ _)
	| Just tg <- nameToTag nm = FeatureTag tg e
toFeature e = FeatureRaw e

fromFeature :: Feature -> Element
fromFeature (FeatureVer o) = Element
	(fromJust $ lookup TagVer tagName) [] . (: []) . NodeElement $ case o of
		Optional -> Element (fromJust $ lookup TagOptional tagName) [] []
		VerRaw e -> e
fromFeature (FeatureBind o) = Element
	(fromJust $ lookup TagBind tagName) [] . (: []) . NodeElement $ case o of
		Required -> Element (fromJust $ lookup TagRequired tagName) [] []
		BindRaw e -> e
		_ -> error "fromFeature: error"
fromFeature (FeatureSession o) = Element (fromJust $ lookup TagSession tagName)
	[] . (: []) . NodeElement $ case o of
		SessionOptional -> Element
			(fromJust $ lookup TagSessionOptional tagName) [] []
		SessionRaw e -> e
fromFeature (FeatureC c) =
	flip (Element (fromJust $ lookup TagC tagName)) [] $ fromCaps c
fromFeature (FeatureTag _ e) = e
fromFeature (FeatureRaw e) = e

lookupAttr :: Text -> [(Name, [Content])] -> Text
lookupAttr bs ats = case filter ((== Name bs Nothing Nothing) . fst) ats of
	[(_, [ContentText txt])] -> txt
	_ -> error "lookupAttr: bad"

lookupAttrM :: Text -> [(Name, [Content])] -> Maybe Text
lookupAttrM bs ats = case filter ((== Name bs Nothing Nothing) . fst) ats of
	[(_, [ContentText txt])] -> Just txt
	_ -> Nothing

data Challenge
	= Challenge {
		realm :: ByteString,
		nonce :: ByteString,
		qop :: ByteString,
		charset :: ByteString,
		algorithm :: ByteString
	 }
	| ChallengeRspauth ByteString
	| ChallengeRaw [(ByteString, ByteString)]
	deriving Show

toChallenge :: [(ByteString, ByteString)] -> Challenge
toChallenge kvs
	| sort (map fst kvs) ==
		sort ["realm", "nonce", "qop", "charset", "algorithm"] =
		Challenge {
			realm = unquoteBS $ lu "realm" kvs,
			nonce = unquoteBS $ lu "nonce" kvs,
			qop = unquoteBS $ lu "qop" kvs,
			charset = lu "charset" kvs,
			algorithm = lu "algorithm" kvs
		 }
	where
	lu = (fromJust .) . lookup
toChallenge [("rspauth", rsp)] = ChallengeRspauth rsp
toChallenge kvs = ChallengeRaw kvs

fromChallenge :: Challenge -> [(ByteString, ByteString)]
fromChallenge c@(Challenge {}) = [
	("realm", quoteBS $ realm c),
	("nonce", quoteBS $ nonce c),
	("qop", quoteBS $ qop c),
	("charset", charset c),
	("algorithm", algorithm c)
 ]
fromChallenge (ChallengeRspauth rsp) = [("rspauth", rsp)]
fromChallenge (ChallengeRaw kvs) = kvs

data Response
	= Response {
		rUsername :: ByteString,
		rRealm :: ByteString,
		rPassword :: ByteString,
		rCnonce :: ByteString,
		rNonce :: ByteString,
		rNc :: ByteString,
		rQop :: ByteString,
		rDigestUri :: ByteString,
--		rResponse :: ByteString,
		rCharset :: ByteString }
	| ResponseNull
	| ResponseRaw [Node]
	deriving Show

calcMd5 :: Bool -> Response -> ByteString
calcMd5 isClient = digestMd5 isClient
	<$> rUsername <*> rRealm <*> rPassword  <*> rQop <*> rDigestUri
	<*> rNonce <*> rNc <*> rCnonce

toResponse :: [Node] -> Response
toResponse [NodeContent (ContentText txt)]
	| kvs <- readSaslData txt, sort (map fst kvs) == sort [
			"username", "realm", "nonce", "cnonce", "nc", "qop",
			"digest-uri", "response", "charset" ] =
		kvsToResponse kvs
toResponse [] = ResponseNull
toResponse nds = ResponseRaw nds

kvsToResponse :: [(ByteString, ByteString)] -> Response
kvsToResponse kvs = Response {
		rUsername = unquoteBS $ lu "username" kvs,
		rRealm = unquoteBS $ lu "realm" kvs,
		rPassword = "password",
		rNonce = unquoteBS $ lu "nonce" kvs,
		rCnonce = unquoteBS $ lu "cnonce" kvs,
		rNc = lu "nc" kvs,
		rQop = lu "qop" kvs,
		rDigestUri = unquoteBS $ lu "digest-uri" kvs,
--		rResponse = lu "response" kvs,
		rCharset = lu "charset" kvs
	 }
	where
	lu = (fromJust .) . lookup

fromResponse :: Response -> [Node]
fromResponse rsp@(Response {}) =
	[NodeContent . ContentText . showSaslData $ responseToKvs rsp]
fromResponse ResponseNull = []
fromResponse (ResponseRaw nds) = nds

responseToKvs :: Response -> [(ByteString, ByteString)]
responseToKvs rsp = [
	("username", quoteBS $ rUsername rsp),
	("realm", quoteBS $ rRealm rsp),
	("nonce", quoteBS $ rNonce rsp),
	("cnonce", quoteBS $ rCnonce rsp),
	("nc", rNc rsp),
	("qop", rQop rsp),
	("digest-uri", quoteBS $ rDigestUri rsp),
	("response", calcMd5 True rsp),
--	("response", rResponse rsp),
	("charset", rCharset rsp)
 ]

data Tag
	= TagFeatures
	| Mechanisms
	| Mechanism
	| Auth
	| TagChallenge
	| TagResponse
	| TagSuccess
	| TagVer
	| TagBind
	| TagOptional
	| TagRequired
	| TagSession
	| TagSessionOptional
	| TagC
	| TagIq
	| TagResource
	| TagJid
	| TagRosterQuery
	| TagPresence
	| TagDiscoQuery
	| TagMessage
	deriving (Show, Eq)

data Mechanism
	= ScramSha1
	| DigestMd5
	| UnknownMechanism Text
	| NotMechanism Element
	deriving (Show, Eq)

elementToStanza :: Element -> Stanza
elementToStanza (Element nm [] (NodeElement (Element nm' [] nds) : _))
	| Just TagFeatures <- nameToTag nm,
		Just Mechanisms <- nameToTag nm' =
		StanzaMechanismList $ map
			(elementToMechanism . fromJust . nodeElementElement) nds
elementToStanza (Element nm
	[(Name "mechanism" Nothing Nothing, [ContentText at])] [])
	| Just Auth <- nameToTag nm = StanzaMechanism $ case at of
		"SCRAM-SHA-1" -> ScramSha1
		"DIGEST-MD5" -> DigestMd5
		_ -> UnknownMechanism at
elementToStanza (Element nm [] [NodeContent (ContentText cnt)])
	| Just TagChallenge <- nameToTag nm = StanzaChallenge . toChallenge $
		readSaslData cnt
elementToStanza (Element nm [] nds)
	| Just TagResponse <- nameToTag nm = StanzaResponse $ toResponse nds
elementToStanza (Element nm [] [])
	| Just TagSuccess <- nameToTag nm = StanzaSuccess
elementToStanza (Element nm [] nds)
	| Just TagFeatures <- nameToTag nm =
		StanzaFeatureList $ map (toFeature . \(NodeElement e) -> e) nds
elementToStanza (Element nm ats [])
	| Just TagIq <- nameToTag nm = StanzaIq {
		iqId = lookupAttr "id" ats,
		iqType = toIqType $ lookupAttr "type" ats,
		iqTo = lookupAttrM "to" ats,
		iqBody = IqBodyNull
	 }
elementToStanza (Element nm ats [NodeElement e])
	| Just TagIq <- nameToTag nm = StanzaIq {
		iqId = lookupAttr "id" ats,
		iqType = toIqType $ lookupAttr "type" ats,
		iqTo = lookupAttrM "to" ats,
		iqBody = toIqBody e
	 }
elementToStanza (Element nm ats nds)
	| Just TagPresence <- nameToTag nm = StanzaPresence {
		presenceId = lookupAttr "id" ats,
		presenceBody = map (toPresenceBody . \(NodeElement e) -> e) nds
	 }
elementToStanza (Element nm ats nds)
	| Just TagMessage <- nameToTag nm = StanzaMessage {
		messageType = lookupAttr "type" ats,
		messageId = lookupAttr "id" ats,
		messageFrom = lookupAttrM "from" ats,
		messageTo = lookupAttrM "to" ats,
		messageBody = nds }
elementToStanza e@(Element n _ _)
	| Just t <- nameToTag n = StanzaTag t e
	| otherwise = StanzaRaw e

readSaslData :: Text -> [(ByteString, ByteString)]
readSaslData = map ((\[k, v] -> (k, v)) . BSC.split '=') . BSC.split ',' .
	(\(Right c) -> c) . B64.decode . encodeUtf8

stanzaToElement :: Stanza -> Element
stanzaToElement (StanzaMechanismList nds) = Element
	(fromJust $ lookup TagFeatures tagName) [] [NodeElement e]
	where
	e = Element (fromJust $ lookup Mechanisms tagName) [] $
		map (NodeElement . mechanismToElement) nds
stanzaToElement (StanzaMechanism at)
	| Just c <- mct = Element (fromJust $ lookup Auth tagName)
		[(Name "mechanism" Nothing Nothing, [c])] []
	where
	mct = case at of
		ScramSha1 -> Just $ ContentText "SCRAM-SHA-1"
		DigestMd5 -> Just $ ContentText "DIGEST-MD5"
		UnknownMechanism mn -> Just $ ContentText mn
		_ -> Nothing
stanzaToElement (StanzaChallenge cnt) = Element
	(fromJust $ lookup TagChallenge tagName) [] . (: []) . NodeContent .
		ContentText .  showSaslData $
			fromChallenge cnt
stanzaToElement (StanzaResponse rp) = Element
	(fromJust $ lookup TagResponse tagName) [] $ fromResponse rp
stanzaToElement StanzaSuccess = Element
	(fromJust $ lookup TagSuccess tagName) [] []
stanzaToElement (StanzaFeatureList fts) = Element
	(fromJust $ lookup TagFeatures tagName) [] $
		map (NodeElement . fromFeature) fts
stanzaToElement s@(StanzaIq {})
	| IqBodyNull <- iqBody s =
		flip (Element . fromJust $ lookup TagIq tagName) [] [
			(Name "id" Nothing Nothing, [ContentText $ iqId s]),
			(Name "type" Nothing Nothing,
				[ContentText . fromIqType $ iqType s]) ]
	| otherwise =
		flip (Element . fromJust $ lookup TagIq tagName)
			[NodeElement . fromIqBody $ iqBody s] $ [
				(Name "id" Nothing Nothing,
					[ContentText $ iqId s]),
				(Name "type" Nothing Nothing,
					[ContentText . fromIqType $ iqType s]) ] ++
				maybe [] (: [(Name "from" Nothing Nothing, [ContentText ""])]) ((Name "to" Nothing Nothing ,)
					. (: [])
					. ContentText <$>  iqTo s)
--				(Name "to" Nothing Nothing,
--					maybe [] ((: []) . ContentText) $ iqTo s)
--			 ]
stanzaToElement s@(StanzaPresence {}) =
	Element (fromJust $ lookup TagPresence tagName)
		[(Name "id" Nothing Nothing, [ContentText $ presenceId s])]
		(map (NodeElement . fromPresenceBody) $ presenceBody s)
stanzaToElement s@(StanzaMessage {}) =
	flip (Element . fromJust $ lookup TagMessage tagName) (messageBody s) [
		(Name "id" Nothing Nothing, [ContentText $ messageId s]),
		(Name "type" Nothing Nothing, [ContentText $ messageType s]),
		(Name "from" Nothing Nothing,
			maybe [] ((: []) . ContentText) $ messageFrom s),
		(Name "to" Nothing Nothing,
			maybe [] ((: []) . ContentText) $ messageTo s) ]
stanzaToElement (StanzaTag _ e) = e
stanzaToElement (StanzaRaw e) = e
stanzaToElement _ = error "stanzaToElement: error"

showSaslData :: [(ByteString, ByteString)] -> Text
showSaslData = decodeUtf8 . B64.encode . BSC.intercalate "," .
	map (BSC.intercalate "=" . (\(k, v) -> [k, v]))

elementToMechanism :: Element -> Mechanism
elementToMechanism e@(Element nm [] [NodeContent (ContentText mn)])
	| Just Mechanism <- nameToTag nm = case mn of
		"SCRAM-SHA-1" -> ScramSha1
		"DIGEST-MD5" -> DigestMd5
		_ -> UnknownMechanism mn
	| otherwise = NotMechanism e
elementToMechanism e = NotMechanism e

mechanismToElement :: Mechanism -> Element
mechanismToElement (NotMechanism e) = e
mechanismToElement m = let Just nm = lookup Mechanism tagName in
	Element nm [] . (: []) . NodeContent . ContentText $ case m of
		ScramSha1 -> "SCRAM-SHA-1"
		DigestMd5 -> "DIGEST-MD5"
		UnknownMechanism mn -> mn
		NotMechanism _ -> error "mechanismToElement: never occur"

tagName :: [(Tag, Name)]
tagName = [
	(TagFeatures, Name "features"
		(Just "http://etherx.jabber.org/streams") (Just "stream")),
	(Mechanisms, Name "mechanisms"
		(Just "urn:ietf:params:xml:ns:xmpp-sasl") Nothing),
	(Mechanism, Name "mechanism"
		(Just "urn:ietf:params:xml:ns:xmpp-sasl") Nothing),
	(Mechanism, Name "mechanism" Nothing Nothing),
	(Auth, Name "auth"
		(Just "urn:ietf:params:xml:ns:xmpp-sasl") Nothing),
	(TagChallenge, Name "challenge"
		(Just "urn:ietf:params:xml:ns:xmpp-sasl") Nothing),
	(TagResponse, Name "response"
		(Just "urn:ietf:params:xml:ns:xmpp-sasl") Nothing),
	(TagSuccess, Name "success"
		(Just "urn:ietf:params:xml:ns:xmpp-sasl") Nothing),
	(TagVer, Name "ver"
		(Just "urn:xmpp:features:rosterver") Nothing),
	(TagBind, Name "bind"
		(Just "urn:ietf:params:xml:ns:xmpp-bind") Nothing),
	(TagOptional, Name "optional"
		(Just "urn:xmpp:features:rosterver") Nothing),
	(TagRequired, Name "required"
		(Just "urn:ietf:params:xml:ns:xmpp-bind") Nothing),
	(TagSession, Name "session"
		(Just "urn:ietf:params:xml:ns:xmpp-session") Nothing),
	(TagSessionOptional, Name "optional"
		(Just "urn:ietf:params:xml:ns:xmpp-session") Nothing),
	(TagC, Name "c"
		(Just "http://jabber.org/protocol/caps") Nothing),
	(TagIq, Name "iq" (Just "jabber:client") Nothing),
	(TagResource, Name "resource"
		(Just "urn:ietf:params:xml:ns:xmpp-bind") Nothing),
	(TagJid, Name "jid"
		(Just "urn:ietf:params:xml:ns:xmpp-bind") Nothing),
	(TagRosterQuery, Name "query" (Just "jabber:iq:roster") Nothing),
	(TagPresence, Name "presence" (Just "jabber:client") Nothing),
	(TagDiscoQuery, Name "query"
		(Just "http://jabber.org/protocol/disco#info") Nothing),
	(TagMessage, Name "message" (Just "jabber:client") Nothing)
 ]

nameToTag :: Name -> Maybe Tag
nameToTag = flip lookup $ map (\(x, y) -> (y, x)) tagName

nodeElementElement :: Node -> Maybe Element
nodeElementElement (NodeElement e) = Just e
nodeElementElement _ = Nothing

unquoteBS :: ByteString -> ByteString
unquoteBS bs = case BSC.uncons bs of
	Just ('"', t) -> case unsnoc t of
		Just (i, '"') -> i
		_ -> error "unquoteBS: not quoted"
	_ -> error "unquoteBS: not quoted"

unsnoc :: ByteString -> Maybe (ByteString, Char)
unsnoc bs
	| BSC.null bs = Nothing
	| otherwise = Just (BSC.init bs, BSC.last bs)

quoteBS :: ByteString -> ByteString
quoteBS bs = "\"" `BS.append` bs `BS.append` "\""
