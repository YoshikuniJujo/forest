{-# LANGUAGE OverloadedStrings, TypeFamilies, TupleSections, FlexibleContexts,
	PackageImports #-}

import Data.UUID
import System.Random

import Control.Applicative
import Control.Arrow
import Control.Monad
import "monads-tf" Control.Monad.State
import Control.Concurrent (forkIO)
import Data.Maybe
import Data.Pipe
import Data.HandleLike
import Text.XML.Pipe
import Network

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Base64 as B64

import DigestSv
import Papillon

data SHandle s h = SHandle h

instance HandleLike h => HandleLike (SHandle s h) where
	type HandleMonad (SHandle s h) = StateT s (HandleMonad h)
	type DebugLevel (SHandle s h) = DebugLevel h
	hlPut (SHandle h) = lift . hlPut h
	hlGet (SHandle h) = lift . hlGet h
	hlClose (SHandle h) = lift $ hlClose h
	hlDebug (SHandle h) = (lift .) . hlDebug h

main :: IO ()
main = do
	socket <- listenOn $ PortNumber 5222
	forever $ do
		(h, _, _) <- accept socket
		uuids <- randoms <$> getStdGen
		voidM . forkIO . (`evalStateT` initXmppState uuids)
			. xmpp $ SHandle h

data XmppState = XmppState {
	sequenceNumber :: Int,
	uuidList :: [UUID] }

initXmppState :: [UUID] -> XmppState
initXmppState uuids = XmppState {
	sequenceNumber = 0,
	uuidList = uuids }

modifySequenceNumber :: (Int -> Int) -> XmppState -> XmppState
modifySequenceNumber f xs = xs { sequenceNumber = f $ sequenceNumber xs }

nextUuid :: (MonadState m, StateType m ~ XmppState) => m UUID
nextUuid = do
	xs@XmppState { uuidList = u : us } <- get
	put xs { uuidList = us }
	return u

xmpp :: (MonadState (HandleMonad h), StateType (HandleMonad h) ~ XmppState,
		HandleLike h) => h -> HandleMonad h ()
xmpp h = do
	voidM . runPipe $ input h =$= makeP =$= output h
	hlPut h $ xmlString [XmlEnd (("stream", Nothing), "stream")]
	hlClose h

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

checkP :: (HandleLike h, Show a) => h -> Pipe a a (HandleMonad h) ()
checkP h = do
	mx <- await
	case mx of
		Just x -> do
			lift . hlDebug h "critical" . BSC.pack . (++ "\n") $ show x
			yield x
			checkP h
		_ -> return ()

xmlPipe :: Monad m => Pipe XmlEvent XmlNode m ()
xmlPipe = xmlBegin >>= xmlNode >>= flip when xmlPipe

data ShowResponse
	= SRXmlDecl
	| SRStream [(Tag, BS.ByteString)]
	| SRFeatures [Feature]
	| SRAuth Mechanism
	| SRChallenge Challenge
	| SRResponse BS.ByteString DigestResponse
	| SRChallengeRspauth DigestResponse
	| SRResponseNull
	| SRSuccess
	| SRIq [(Tag, BS.ByteString)] [Iq]
	| SRPresence [(Tag, BS.ByteString)] [XmlNode]
	| SRMessage MessageType BS.ByteString Jid Jid [XmlNode]
	| SRRaw XmlNode
	deriving Show

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

data Challenge
	= Challenge {
		crealm :: BS.ByteString,
		cnonce :: UUID }
	| ChallengeRaw [XmlNode]
	deriving Show

fromChallenge :: Challenge -> [XmlNode]
fromChallenge c@Challenge{} = (: []) . XmlCharData . B64.encode $ BS.concat [
	"realm=", BSC.pack . show $ crealm c, ",",
	"nonce=", BSC.pack . show . toASCIIBytes $ cnonce c, ",",
	"qop=\"auth\",",
	"charset=utf-8,",
	"algorithm=md5-sess" ]
fromChallenge (ChallengeRaw ns) = ns

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

data Mechanism
	= ScramSha1 | DigestMd5 | Plain | MechanismRaw BS.ByteString
	deriving (Eq, Show)

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

data Requirement = Optional | Required deriving Show

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
	as) = SRStream $ map (first toTag) as
showResponse (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "auth")
	_ as [])
	| [(Mechanism, m)] <- map (first toTag) as = SRAuth $ toMechanism m
showResponse (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "response")
	_ [] []) = SRResponseNull
showResponse (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "response")
	_ [] [XmlCharData cd]) = let
		Just a = parseAtts . (\(Right s) -> s) $ B64.decode cd
		in
		SRResponse (fromJust $ lookup "response" a) $ DR {
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

data Tag
	= Id | From | To | Version | Lang | Mechanism | Type
	| TagRaw QName
	deriving (Eq, Show)

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
toXml SRXmlDecl = XmlDecl (1, 0)
toXml (SRStream as) = XmlStart (("stream", Nothing), "stream")
	[	("", "jabber:client"),
		("stream", "http://etherx.jabber.org/streams") ]
	(map (first fromTag) as)
toXml (SRFeatures fs) = XmlNode (("stream", Nothing), "features") [] [] $
	map fromFeature fs
toXml (SRChallenge c) = XmlNode (nullQ "challenge")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")] [] $ fromChallenge c
toXml (SRChallengeRspauth dr) = let
	sret = B64.encode . ("rspauth=" `BS.append`) . fromJust
		. lookup "response" $ responseToKvs False dr in
	XmlNode (nullQ "challenge")
		[("", "urn:ietf:params:xml:ns:xmpp-sasl")] [] [XmlCharData sret]
toXml SRSuccess =
	XmlNode (nullQ "success") [("", "urn:ietf:params:xml:ns:xmpp-sasl")] [] []
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

sender, receiver :: Jid
sender = Jid "yoshio" "localhost" (Just "profanity")
receiver = Jid "yoshikuni" "localhost" Nothing

caps :: Feature
caps = Caps {
	chash = "sha-1",
	cver = "k07nuHawZqmndRtf3ZfBm54FwL0=",
	cnode = "http://prosody.im" }

makeSR :: (Int, UUID) -> ShowResponse -> [ShowResponse]
makeSR (0, u) (SRStream _) = [
	SRXmlDecl,
	SRStream [
		(Id, toASCIIBytes u),
		(From, "localhost"), (Version, "1.0"), (Lang, "en")],
	SRFeatures [Mechanisms [ScramSha1, DigestMd5]] ]
makeSR (1, u) (SRStream _) = [
	SRXmlDecl,
	SRStream [
		(Id, toASCIIBytes u),
		(From, "localhost"), (Version, "1.0"), (Lang, "en")],
	SRFeatures [Rosterver Optional, Bind Required, Session Optional] ]
makeSR _ (SRStream _) = error "makeR: not implemented"
makeSR (_, u) (SRAuth DigestMd5) =
	(: []) $ SRChallenge Challenge { crealm = "localhost", cnonce = u }
makeSR _ (SRAuth _) = error "makeR: not implemented auth mechanism"
makeSR _ (SRResponse r dr) = let
	cret = fromJust . lookup "response" $ responseToKvs True dr in
	if (r /= cret)
		then error "procR: bad authentication"
		else [SRChallengeRspauth dr]
makeSR _ SRResponseNull = [SRSuccess]
makeSR _ (SRIq [(Id, i), (Type, "set")] [IqBindReq Required (Resource _n)]) =
	map SRRaw $ (: []) $ XmlNode (nullQ "iq") []
		[(nullQ "id", i), (nullQ "type", "result")]
		[XmlNode (nullQ "jid") [] []
			[XmlCharData "yoshikuni@localhost/profanity"]]
makeSR _ (SRIq [(Id, i), (Type, "set")] [IqSession]) = 
	map SRRaw $ (: []) $ XmlNode (nullQ "iq") []
		[	(nullQ "id", i),
			(nullQ "type", "result"),
			(nullQ "to", "yoshikuni@localhost/profanity")
			] []
makeSR _ (SRIq [(Id, i), (Type, "get")] [IqRoster]) =
	map SRRaw $ (: []) $ XmlNode (nullQ "iq") []
		[	(nullQ "id", i),
			(nullQ "type", "result"),
			(nullQ "to", "yoshikuni@localhost/profanity")
			]
		[XmlNode (nullQ "query") [("", "jabber:iq:roster")]
			[(nullQ "ver", "1")] []]
makeSR _ (SRPresence _ _) = (: []) $ SRMessage Chat "hoge" sender receiver
		[XmlNode (nullQ "body") [] [] [XmlCharData "Hogeru"]]
makeSR _ _ = []

makeP :: (MonadState m, StateType m ~ XmppState) =>
	Pipe ShowResponse ShowResponse m ()
makeP = do
	n <- lift $ gets sequenceNumber
	mr <- await
	case mr of
		Just r -> do
			case r of
				SRStream _ -> lift . modify $
					modifySequenceNumber (+ 1)
				_ -> return ()
			u <- lift nextUuid
			mapM_ yield $ makeSR (n, u) r
			makeP
		_ -> return ()

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

printP :: (Show a, HandleLike h) => h -> Pipe a () (HandleMonad h) ()
printP h = await >>= maybe (return ()) (const $ printP h)

showBS :: Show a => a -> BS.ByteString
showBS = BSC.pack . (++ "\n") . show

voidM :: Monad m => m a -> m ()
voidM = (>> return ())

nullQ :: BS.ByteString -> QName
nullQ = (("", Nothing) ,)

convert :: Monad m => (a -> b) -> Pipe a b m ()
convert f = await >>= maybe (return ()) (\x -> yield (f x) >> convert f)
