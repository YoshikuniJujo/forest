{-# LANGUAGE OverloadedStrings, TypeFamilies, TupleSections, FlexibleContexts,
	PackageImports #-}

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
		voidM . forkIO . (`evalStateT` (0 :: Int)) . xmpp $ SHandle h

type XmppState = Int

xmpp :: (MonadState (HandleMonad h), StateType (HandleMonad h) ~ Int,
		HandleLike h) =>
	h -> HandleMonad h ()
xmpp h = do
	voidM . runPipe $ input h =$= process h =$= printP h
	hlPut h "</stream:stream>"
	hlClose h

input :: HandleLike h => h -> Pipe () ShowResponse (HandleMonad h) ()
input h = handleP h
	=$= xmlEvent
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
	= SRStream [(Tag, BS.ByteString)]
	| SRAuth [(Tag, BS.ByteString)]
	| SRResponse BS.ByteString
	| SRResponseNull
	| SRIq [(Tag, BS.ByteString)] [Iq]
	| SRPresence [(Tag, BS.ByteString)] [XmlNode]
	| SRRaw XmlNode
	deriving Show

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
	_ as []) = SRAuth $ map (first toTag) as
showResponse (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "response")
	_ [] []) = SRResponseNull
showResponse (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-sasl"), "response")
	_ [] [XmlCharData cd]) = SRResponse . (\(Right s) -> s) $ B64.decode cd
showResponse (XmlNode ((_, Just "jabber:client"), "iq")
	_ as ns) = SRIq (map (first toTag) as) (map toIq ns)
showResponse (XmlNode ((_, Just "jabber:client"), "presence")
	_ as ns) = SRPresence (map (first toTag) as) ns
showResponse n = SRRaw n

data Tag
	= To | Lang | Version | Mechanism | Id | Type
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

process :: (MonadState (HandleMonad h), StateType (HandleMonad h) ~ XmppState,
		HandleLike h) =>
	h -> Pipe ShowResponse ShowResponse (HandleMonad h) ()
process h = do
	lift . hlPut h . xmlString $ begin ++ authFeatures
	lift . hlPut h . xmlString $ challengeXml
	processResponse h

processResponse ::
	(MonadState (HandleMonad h), StateType (HandleMonad h) ~ XmppState,
		HandleLike h) =>
	h -> Pipe ShowResponse ShowResponse (HandleMonad h) ()
processResponse h = do
	mr <- await
	case mr of
		Just r -> lift (procR h r) >> yield r >> processResponse h
		_ -> return ()

procR :: (MonadState (HandleMonad h), StateType (HandleMonad h) ~ XmppState,
		HandleLike h) =>
	h -> ShowResponse -> HandleMonad h ()
procR h (SRResponse _) = do
	let sret = B64.encode . ("rspauth=" `BS.append`) . fromJust . lookup "response" $
		responseToKvs False sampleDR
	hlPut h . xmlString . (: []) $ XmlNode (nullQ "challenge")
		[("", "urn:ietf:params:xml:ns:xmpp-sasl")] [] [XmlCharData sret]
	hlDebug h "critical" $ sret `BS.append` "\n"
procR h SRResponseNull = hlPut h . xmlString . (: []) $ XmlNode (nullQ "success")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")] [] []
procR h (SRStream _) = do
	n <- get
	modify (+ 1)
	hlDebug h "critical" . BSC.pack . (++ "\n") $ show n
	when (n == 1) . hlPut h . xmlString $ begin' ++ capsFeatures
--	hlPut h $ xmlString begin'
	return ()
procR h (SRIq [(Id, i), (Type, "set")] [IqBindReq Required (Resource _n)]) = do
	hlPut h . xmlString . (: []) $ XmlNode (nullQ "iq") []
		[(nullQ "id", i), (nullQ "type", "result")]
		[XmlNode (nullQ "jid") [] [] [XmlCharData "yoshikuni@localhost/profanity"]]
procR h (SRIq [(Id, i), (Type, "set")] [IqSession]) = do
	hlPut h . xmlString . (: []) $ XmlNode (nullQ "iq") []
		[	(nullQ "id", i),
			(nullQ "type", "result"),
			(nullQ "to", "yoshikuni@localhost/profanity")
			]
		[]
procR h (SRIq [(Id, i), (Type, "get")] [IqRoster]) = do
	hlPut h . xmlString . (: []) $ XmlNode (nullQ "iq") []
		[	(nullQ "id", i),
			(nullQ "type", "result"),
			(nullQ "to", "yoshikuni@localhost/profanity")
			]
		[XmlNode (nullQ "query") [("", "jabber:iq:roster")]
			[(nullQ "ver", "1")] []]
procR h (SRPresence _ _) =
	hlPut h . xmlString . (: []) $ XmlNode (nullQ "message") []
		[	(nullQ "type", "chat"),
			(nullQ "to", "yoshikuni@localhost"),
			(nullQ "from", "yoshio@localhost/profanity"),
			(nullQ "id", "hoge") ]
		[XmlNode (nullQ "body") [] [] [XmlCharData "Hogeru"]]
procR _ _ = return ()

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

begin, begin' :: [XmlNode]
begin = [
	XmlDecl (1, 0),
	XmlStart (("stream", Nothing), "stream")
		[	("", "jabber:client"),
			("stream", "http://etherx.jabber.org/streams") ]
		[	(nullQ "id", "83e074ac-c014-432e-9f21-d06e73f5777e"),
			(nullQ "from", "localhost"),
			(nullQ "version", "1.0"),
			((("xml", Nothing), "lang"), "en") ]
	]
begin' = [
	XmlDecl (1, 0),
	XmlStart (("stream", Nothing), "stream")
		[	("", "jabber:client"),
			("stream", "http://etherx.jabber.org/streams") ]
		[	(nullQ "id", "5b5b55ce-8a9c-4879-b4eb-0231b25a54a4"),
			(nullQ "from", "localhost"),
			(nullQ "version", "1.0"),
			((("xml", Nothing), "lang"), "en") ]
	]

authFeatures :: [XmlNode]
authFeatures = [XmlNode (("stream", Nothing), "features") [] [] [mechanisms]]

capsFeatures :: [XmlNode]
capsFeatures = (: []) $ XmlNode (("stream", Nothing), "features") [] []
	[caps, rosterver, bind, session]

caps :: XmlNode
caps = XmlNode (nullQ "c")
	[("", "http://jabber.org/protocol/caps")]
	[	(nullQ "hash", "sha-1"),
		(nullQ "ver", "k07nuHawZqmndRtf3ZfBm54FwL0="),
		(nullQ "node", "http://prosody.im")
		]
	[]

rosterver :: XmlNode
rosterver = XmlNode (nullQ "ver")
	[("", "urn:xmpp:features:rosterver")]
	[]
	[XmlNode (nullQ "optional") [] [] []]

bind :: XmlNode
bind = XmlNode (nullQ "bind")
	[("", "urn:ietf:params:xml:ns:xmpp-bind")]
	[]
	[XmlNode (nullQ "required") [] [] []]

session :: XmlNode
session = XmlNode (nullQ "session")
	[("", "urn:ietf:params:xml:ns:xmpp-session")]
	[]
	[XmlNode (nullQ "optional") [] [] []]

mechanisms :: XmlNode
mechanisms = XmlNode (nullQ "mechanisms")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")] []
	[	XmlNode (nullQ "mechanism") [] [] [XmlCharData "SCRAM-SHA-1"],
		XmlNode (nullQ "mechanism") [] [] [XmlCharData "DIGEST-MD5"] ]

convert :: Monad m => (a -> b) -> Pipe a b m ()
convert f = await >>= maybe (return ()) (\x -> yield (f x) >> convert f)

challengeXml :: [XmlNode]
challengeXml = (: []) $ XmlNode
	(nullQ "challenge") [("", "urn:ietf:params:xml:ns:xmpp-sasl")] []
	[XmlCharData challenge]

challenge :: BS.ByteString
challenge = B64.encode $ BS.concat [
	"realm=\"localhost\",",
	"nonce=\"90972262-92fe-451d-9526-911f5b8f6e34\",",
	"qop=\"auth\",",
	"charset=utf-8,",
	"algorithm=md5-sess" ]
