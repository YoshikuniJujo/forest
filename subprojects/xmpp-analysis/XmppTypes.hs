{-# LANGUAGE OverloadedStrings #-}

module XmppTypes (
	elementToStanza,
	stanzaToElement
) where

import Data.Maybe
import Data.XML.Types
import Data.Text (Text)

data Stanza
	= StanzaMechanismList [Mechanism]
	| StanzaMechanism Mechanism
	| StanzaTag Tag Element
	| StanzaRaw Element
	deriving Show

data Tag
	= Features
	| Mechanisms
	| Mechanism
	| Auth
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
		(Just "urn:ietf:params:xml:ns:xmpp-sasl") Nothing)
 ]

nameToTag :: Name -> Maybe Tag
nameToTag = flip lookup $ map (\(x, y) -> (y, x)) tagName

nodeElementElement :: Node -> Maybe Element
nodeElementElement (NodeElement e) = Just e
nodeElementElement _ = Nothing
