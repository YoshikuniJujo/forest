{-# LANGUAGE OverloadedStrings #-}

module XmppTypes (
	elementToStanza,
	stanzaToElement
) where

import Control.Arrow
import Data.Maybe
import Data.List
import Data.XML.Types
import Data.Text (Text)
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Base64 as B64

data Stanza
	= StanzaMechanismList [Mechanism]
	| StanzaMechanism Mechanism
	| StanzaChallenge Challenge
	| StanzaTag Tag Element
	| StanzaRaw Element
	deriving Show

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

data Tag
	= Features
	| Mechanisms
	| Mechanism
	| Auth
	| TagChallenge
	deriving (Show, Eq)

data Mechanism
	= ScramSha1
	| DigestMd5
	| UnknownMechanism Text
	| NotMechanism Element
	deriving Show

elementToStanza :: Element -> Stanza
elementToStanza (Element nm [] [NodeElement nd@(Element nm' [] nds)])
	| Just Features <- nameToTag nm,
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
	| Just TagChallenge <- nameToTag nm = StanzaChallenge . toChallenge .
		map ((\[k, v] -> (k, v)) . BSC.split '=') .  BSC.split ',' .
		(\(Right c) -> c) . B64.decode $ encodeUtf8 cnt
elementToStanza e@(Element n _ _)
	| Just t <- nameToTag n = StanzaTag t e
	| otherwise = StanzaRaw e

stanzaToElement :: Stanza -> Element
stanzaToElement (StanzaMechanismList nds) = Element
	(fromJust $ lookup Features tagName) [] [NodeElement e]
	where
	e = Element (fromJust $ lookup Mechanisms tagName) [] $ map NodeElement $
		map mechanismToElement nds
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
		ContentText . decodeUtf8 . B64.encode .  BSC.intercalate "," .
		map (BSC.intercalate "=" . (\(k, v) -> [k, v])) $
			fromChallenge cnt
stanzaToElement (StanzaTag _ e) = e
stanzaToElement (StanzaRaw e) = e

elementToMechanism :: Element -> Mechanism
elementToMechanism e@(Element nm [] [NodeContent (ContentText mn)])
	| Just Mechanism <- nameToTag nm = case mn of
		"SCRAM-SHA-1" -> ScramSha1
		"DIGEST-MD5" -> DigestMd5
		_ -> UnknownMechanism mn
	| otherwise = NotMechanism e

mechanismToElement :: Mechanism -> Element
mechanismToElement (NotMechanism e) = e
mechanismToElement m = let Just nm = lookup Mechanism tagName in
	Element nm [] . (: []) . NodeContent . ContentText $ case m of
		ScramSha1 -> "SCRAM-SHA-1"
		DigestMd5 -> "DIGEST-MD5"
		UnknownMechanism mn -> mn

tagName :: [(Tag, Name)]
tagName = [
	(Features, Name "features"
		(Just "http://etherx.jabber.org/streams") (Just "stream")),
	(Mechanisms, Name "mechanisms"
		(Just "urn:ietf:params:xml:ns:xmpp-sasl") Nothing),
	(Mechanism, Name "mechanism"
		(Just "urn:ietf:params:xml:ns:xmpp-sasl") Nothing),
	(Mechanism, Name "mechanism" Nothing Nothing),
	(Auth, Name "auth"
		(Just "urn:ietf:params:xml:ns:xmpp-sasl") Nothing),
	(TagChallenge, Name "challenge"
		(Just "urn:ietf:params:xml:ns:xmpp-sasl") Nothing)
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
