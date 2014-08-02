{-# LANGUAGE OverloadedStrings, TupleSections #-}

module Caps (
	Caps(..), Identity(..), mkHash, capsToXml, capsToQuery, profanityCaps) where

import Control.Applicative
import Data.Maybe
import Data.List
import Text.XML.Pipe
import Crypto.Hash.SHA1
import Data.ByteString.Base64

import qualified Data.ByteString as BS

data Caps = Caps [Identity] [BS.ByteString] deriving Show

data Identity = Identity {
	idCategory :: BS.ByteString,
	idType :: Maybe BS.ByteString,
	idLang :: Maybe BS.ByteString,
	idName :: Maybe BS.ByteString }
	deriving (Eq, Ord, Show)

serialize :: Identity -> BS.ByteString
serialize i = BS.concat [
	idCategory i, "/",
	fromMaybe "" $ idType i, "/",
	fromMaybe "" $ idLang i, "/",
	fromMaybe "" $ idName i ]

capsToXml :: Caps -> BS.ByteString -> XmlNode
capsToXml c n = XmlNode (nullQ "c")
	[("", "http://jabber.org/protocol/caps")]
	[(nullQ "hash", "sha-1"), (nullQ "node", n), (nullQ "ver", mkHash c)] []

mkHash :: Caps -> BS.ByteString
mkHash (Caps ids fs) = encode . hash . BS.concat . map (`BS.append` "<") $
	map serialize (sort ids) ++ sort fs

nullQ :: BS.ByteString -> QName
nullQ = (("", Nothing) ,)

capsToQuery :: Caps -> BS.ByteString -> XmlNode
capsToQuery (Caps ids fs) nd = XmlNode (nullQ "query")
	[("", "http://jabber.org/protocol/disco#info")]
	[(nullQ "node", nd)]
	$ map identityToXml ids ++ map featureToXml fs

identityToXml :: Identity -> XmlNode
identityToXml i = XmlNode (nullQ "identity") [] (catMaybes [
	Just (nullQ "category", idCategory i),
	(nullQ "type" ,) <$> idType i,
	(nullQ "lang" ,) <$> idLang i,
	(nullQ "name" ,) <$> idName i ]) []

featureToXml :: BS.ByteString -> XmlNode
featureToXml f =
	XmlNode (nullQ "feature") [] [(nullQ "var", f)] []

_sampleId :: Identity
_sampleId = Identity {
	idCategory = "client",
	idType = Just "pc",
	idLang = Nothing,
	idName = Just "Exodus 0.9.1" }

_sampleFeatures :: [BS.ByteString]
_sampleFeatures = [
	"http://jabber.org/protocol/caps",
	"http://jabber.org/protocol/disco#info",
	"http://jabber.org/protocol/disco#items",
	"http://jabber.org/protocol/muc" ]

profanityCaps :: Caps
profanityCaps = Caps
	[Identity "client" (Just "console") Nothing (Just "Profanity 0.4.0")] [
		"http://jabber.org/protocol/caps",
		"http://jabber.org/protocol/chatstates",
		"http://jabber.org/protocol/disco#info",
		"http://jabber.org/protocol/disco#items",
		"http://jabber.org/protocol/muc",
		"jabber:iq:version",
		"urn:xmpp:ping" ]
