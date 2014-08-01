{-# LANGUAGE OverloadedStrings #-}

module Common (
	Common(..), Tag(..), Mechanism(..), Requirement(..),
	Feature(..), Bind(..), Jid(..), Query(..),
	Roster(..), Identity(..), IdentityTag(..),
	DiscoTag(..), InfoFeature(..), InfoFeatureTag(..),
	toDiscoTag, toIdentity, toInfoFeature,
	) where

import Control.Arrow
import Text.XML.Pipe
import qualified Data.ByteString as BS
import qualified Caps as CAPS

import Digest

data Common
	= SRXmlDecl
	| SRStream [(Tag, BS.ByteString)]
	| SRFeatures [Feature]
	| SRAuth Mechanism
	| SRChallenge {
		realm :: BS.ByteString,
		nonce :: BS.ByteString,
		qop :: BS.ByteString,
		charset :: BS.ByteString,
		algorithm :: BS.ByteString }
	| SRResponse BS.ByteString DigestResponse
	| SRChallengeRspauth BS.ByteString
	| SRResponseNull
	| SRSaslSuccess
	deriving Show

data Tag
	= Id | From | To | Version | Lang | Mechanism | Type
	| TagRaw QName
	deriving (Eq, Show)

data Mechanism
	= ScramSha1 | DigestMd5 | Plain | MechanismRaw BS.ByteString
	deriving (Eq, Show)

data Requirement = Optional | Required | NoRequirement [XmlNode]
	deriving (Eq, Show)

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

data Bind
	= Resource BS.ByteString
	| BJid Jid
	| BindRaw XmlNode
	deriving Show

data Jid = Jid BS.ByteString BS.ByteString (Maybe BS.ByteString) deriving (Eq, Show)

data Query
	= IqBind (Maybe Requirement) Bind
	| IqSession
	| IqSessionNull
	| IqRoster (Maybe Roster)
	| QueryRaw [XmlNode]

	| IqCapsQuery BS.ByteString BS.ByteString
	| IqCapsQuery2 CAPS.Caps BS.ByteString
	| IqDiscoInfo
	| IqDiscoInfoNode [(DiscoTag, BS.ByteString)]
	| IqDiscoInfoFull [(DiscoTag, BS.ByteString)] Identity [InfoFeature]
	deriving Show

data DiscoTag = DTNode | DTRaw QName deriving (Eq, Show)

toDiscoTag :: QName -> DiscoTag
toDiscoTag ((_, Just "http://jabber.org/protocol/disco#info"), "node") = DTNode
toDiscoTag n = DTRaw n

data Roster
	= Roster (Maybe BS.ByteString) [XmlNode]
	deriving Show

data InfoFeature
	= InfoFeature BS.ByteString
	| InfoFeatureSemiRaw [(InfoFeatureTag, BS.ByteString)]
	| InfoFeatureRaw XmlNode
	deriving Show

toInfoFeature :: XmlNode -> InfoFeature
toInfoFeature (XmlNode ((_, Just "http://jabber.org/protocol/disco#info"),
	"feature") _ as []) = case map (first toInfoFeatureTag) as of
		[(IFTVar, v)] -> InfoFeature v
		atts -> InfoFeatureSemiRaw atts
toInfoFeature n = InfoFeatureRaw n

data InfoFeatureTag
	= IFTVar
	| IFTVarRaw QName
	deriving (Eq, Show)

toInfoFeatureTag :: QName -> InfoFeatureTag
toInfoFeatureTag ((_, Just "http://jabber.org/protocol/disco#info"), "var") = IFTVar
toInfoFeatureTag n = IFTVarRaw n

data Identity
	= Identity [(IdentityTag, BS.ByteString)]
	| IdentityRaw XmlNode
	deriving Show

data IdentityTag
	= IDTType | IDTName | IDTCategory | IDTRaw QName deriving (Eq, Show)

toIdentityTag :: QName -> IdentityTag
toIdentityTag ((_, Just "http://jabber.org/protocol/disco#info"), "type") = IDTType
toIdentityTag ((_, Just "http://jabber.org/protocol/disco#info"), "name") = IDTName
toIdentityTag ((_, Just "http://jabber.org/protocol/disco#info"), "category") =
	IDTCategory
toIdentityTag n = IDTRaw n

toIdentity :: XmlNode -> Identity
toIdentity (XmlNode ((_, Just "http://jabber.org/protocol/disco#info"), "identity")
	_ as []) = Identity $ map (first toIdentityTag) as
toIdentity n = IdentityRaw n
