{-# LANGUAGE OverloadedStrings #-}

module XmppTypes (
	elementToStanza,
	stanzaToElement
) where

import Data.Maybe
import Data.XML.Types

data Stanza
	= Auth Mechanism
	| StanzaMechanisms [Element]
	| StanzaTag Tag Element
	| StanzaRaw Element
	deriving Show

data Tag
	= Features
	| Mechanisms
	deriving (Show, Eq)

data Mechanism
	= DigestMd5
	deriving Show

elementToStanza :: Element -> Stanza
elementToStanza (Element nm [] [NodeElement nd@(Element nm' [] nds)])
	| Just Features <- nameToTag nm,
		Just Mechanisms <- nameToTag nm' =
		StanzaMechanisms $ map (fromJust . nodeElementElement) nds
elementToStanza e@(Element n _ _)
	| Just t <- nameToTag n = StanzaTag t e
	| otherwise = StanzaRaw e

stanzaToElement :: Stanza -> Element
stanzaToElement (StanzaMechanisms nds) = Element
	(fromJust $ lookup Features tagName) [] [NodeElement e]
	where
	e = Element (fromJust $ lookup Mechanisms tagName) [] $ map NodeElement nds
stanzaToElement (StanzaTag _ e) = e
stanzaToElement (StanzaRaw e) = e

tagName :: [(Tag, Name)]
tagName = [
	(Features, Name "features"
		(Just "http://etherx.jabber.org/streams") (Just "stream")),
	(Mechanisms, Name "mechanisms"
		(Just "urn:ietf:params:xml:ns:xmpp-sasl") Nothing)
 ]

nameToTag :: Name -> Maybe Tag
nameToTag = flip lookup $ map (\(x, y) -> (y, x)) tagName

nodeElementElement :: Node -> Maybe Element
nodeElementElement (NodeElement e) = Just e
nodeElementElement _ = Nothing
