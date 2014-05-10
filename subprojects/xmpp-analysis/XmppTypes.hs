module XmppTypes (
) where

import Data.XML.Types

data Stanza
	= Auth Mechanism
	deriving Show

data Mechanism
	= DigestMd5
	deriving Show

elementToStanza :: Element -> Maybe Stanza
elementToStanza _ = Nothing

stanzaToElement :: Stanza -> Element
stanzaToElement _ = undefined
