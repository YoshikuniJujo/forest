{-# LANGUAGE OverloadedStrings, TypeFamilies, TupleSections, FlexibleContexts,
	PackageImports #-}

module XmppServer (
	MBody(..),
	MessageBody(..),
	Common(..),
	convert,
	nullQ,
	handleP,
	checkP,
	digestMd5,
	showResponse, toXml,
	Jid(..),
	MessageType(..), messageTypeToAtt, IqType(..), iqTypeToAtt,
	Query(..), toIqBody,
	Roster(..),
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
	HandleLike h) => h -> Pipe Common () (HandleMonad h) ()
output h = convert toXml =$= outputXml h

input :: HandleLike h => h -> Pipe () Common (HandleMonad h) ()
input h = handleP h
	=$= xmlEvent
--	=$= checkP h
	=$= convert fromJust
	=$= xmlPipe
	=$= convert showResponse
	=$= checkP h

xmlPipe :: Monad m => Pipe XmlEvent XmlNode m ()
xmlPipe = xmlBegin >>= xmlNode >>= flip when xmlPipe

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

showResponse n = SRRaw n

toXml :: Common -> XmlNode
toXml (SRXmlDecl) = XmlDecl (1, 0)
toXml (SRStream as) = XmlStart (("stream", Nothing), "stream")
	[	("", "jabber:client"),
		("stream", "http://etherx.jabber.org/streams") ]
	(map (first fromTag) as)
toXml (SRFeatures fs) = XmlNode
	(("stream", Nothing), "features") [] [] $ map fromFeature fs
toXml c@SRChallenge{} = XmlNode (nullQ "challenge")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")] [] $ fromChallenge
		(realm c) (nonce c) (qop c) (charset c) (algorithm c)
toXml (SRChallengeRspauth sret) = XmlNode (nullQ "challenge")
	[("", "urn:ietf:params:xml:ns:xmpp-sasl")] [] [XmlCharData sret]
toXml SRSaslSuccess =
	XmlNode (nullQ "success") [("", "urn:ietf:params:xml:ns:xmpp-sasl")] [] []
toXml (SRIq tp i Nothing to q) = XmlNode (nullQ "iq") []
	(catMaybes [
		Just (nullQ "id", i),
		Just $ iqTypeToAtt tp,
		(nullQ "to" ,) . fromJid <$> to ]) 
	(fromQuery q)
toXml (SRMessage tp i (Just fr) to (MBody (MessageBody m))) =
	XmlNode (nullQ "message") []
		[messageTypeToAtt tp,
			(nullQ "from", fromJid fr),
			(nullQ "to", fromJid to),
			(nullQ "id", i) ]
		[XmlNode (nullQ "body") [][] [XmlCharData m]]
toXml (SRRaw n) = n
toXml _ = error "toXml: not implemented"

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

convert :: Monad m => (a -> b) -> Pipe a b m ()
convert f = await >>= maybe (return ()) (\x -> yield (f x) >> convert f)

digestMd5 :: (MonadState m, StateType m ~ XmppState) =>
	UUID -> Pipe Common Common m BS.ByteString
digestMd5 u = do
	yield $ SRFeatures [Mechanisms [DigestMd5]]
	Just (SRAuth DigestMd5) <- await
	yield $ SRChallenge {
		realm = "localhost",
		nonce = toASCIIBytes u,
		qop = "auth",
		charset = "utf-8",
		algorithm = "md5-sess" }
	Just (SRResponse r dr@DR { drUserName = un }) <- await
	let cret = fromJust . lookup "response" $ responseToKvs True dr
	unless (r == cret) $ error "digestMd5: bad authentication"
	let sret = B64.encode . ("rspauth=" `BS.append`) . fromJust
		. lookup "response" $ responseToKvs False dr
	yield $ SRChallengeRspauth sret
	Just SRResponseNull <- await
	yield SRSaslSuccess
	return un
