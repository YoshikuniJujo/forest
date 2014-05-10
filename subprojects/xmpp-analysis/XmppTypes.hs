{-# LANGUAGE OverloadedStrings #-}

module XmppTypes (
	elementToStanza,
	stanzaToElement
) where

import Data.Maybe
import Data.XML.Types
import Data.Text (Text)

data Stanza
	= Auth Mechanism
	| StanzaMechanisms [Mechanism]
	| StanzaTag Tag Element
	| StanzaRaw Element
	deriving Show

data Tag
	= Features
	| Mechanisms
	| Mechanism
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
		StanzaMechanisms $ map
			(elementToMechanism . fromJust . nodeElementElement) nds
elementToStanza e@(Element n _ _)
	| Just t <- nameToTag n = StanzaTag t e
	| otherwise = StanzaRaw e

stanzaToElement :: Stanza -> Element
stanzaToElement (StanzaMechanisms nds) = Element
	(fromJust $ lookup Features tagName) [] [NodeElement e]
	where
	e = Element (fromJust $ lookup Mechanisms tagName) [] $ map NodeElement $
		map mechanismToElement nds
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
		(Just "urn:ietf:params:xml:ns:xmpp-sasl") Nothing)
 ]

nameToTag :: Name -> Maybe Tag
nameToTag = flip lookup $ map (\(x, y) -> (y, x)) tagName

nodeElementElement :: Node -> Maybe Element
nodeElementElement (NodeElement e) = Just e
nodeElementElement _ = Nothing
