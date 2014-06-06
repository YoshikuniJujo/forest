{-# LANGUAGE OverloadedStrings #-}

module Hello (
	Parsable(..), ByteStringM,
	ClientHello(..),
	clientHelloClientRandom, clientHelloClientVersion,
	CipherSuite(..), Random(..),
	SignatureAlgorithm(..), HashAlgorithm(..), CompressionMethod(..),
	SessionId(..), Version(..),

	ServerHello(..),
	serverHelloServerRandom, serverHelloServerVersion, serverHelloCipherSuite,

--	list1,
	evalByteStringM, fst3, fromInt, lenBodyToByteString,
	Extension(..), EcPointFormat(..), NamedCurve(..),
 ) where

import Prelude hiding (take)
import Numeric

import Control.Applicative
import Data.Word
import Data.ByteString (ByteString, pack, unpack)
import qualified Data.ByteString as BS

-- import Types

import Parts(
	Version(..), Parsable(..), CipherSuite(..), Random(..),

	SignatureAlgorithm(..),
	HashAlgorithm(..),
--	Version(..),

	fst3, fromInt,
	lenBodyToByteString, headBS, takeLen,
--	list1,
	evalByteStringM)
import Extension

data ClientHello
	= ClientHello Version Random SessionId [CipherSuite]
		[CompressionMethod] (Maybe ExtensionList)
	| ClientHelloRaw ByteString
	deriving Show

clientHelloClientRandom :: ClientHello -> Maybe Random
clientHelloClientRandom (ClientHello _ r _ _ _ _) = Just r
clientHelloClientRandom _ = Nothing

clientHelloClientVersion :: ClientHello -> Maybe Version
clientHelloClientVersion (ClientHello v _ _ _ _ _) = Just v
clientHelloClientVersion _ = Nothing

instance Parsable ClientHello where
	parse = parseClientHello
	toByteString = clientHelloToByteString
	listLength _ = Nothing

getPvRSid :: ByteStringM (Version, Random, SessionId)
getPvRSid = do
	pv <- parse
	r <- parse
	sid <- parseSessionId
	return (pv, r, sid)

parseClientHello :: ByteStringM ClientHello
parseClientHello = do
	(pv, r, sid) <- getPvRSid
	css <- parse
	cms <- parse
	e <- emptyBS
	mel <- if e then return Nothing else Just <$> parseExtensionList
	return $ ClientHello pv r sid css cms mel

clientHelloToByteString :: ClientHello -> ByteString
clientHelloToByteString (ClientHello pv r sid css cms mel) = BS.concat [
	toByteString pv,
	toByteString r,
	sessionIdToByteString sid,
	toByteString css,
	toByteString cms,
	maybe "" extensionListToByteString mel
 ]
clientHelloToByteString (ClientHelloRaw bs) = bs

data ServerHello
	= ServerHello Version Random SessionId CipherSuite
		CompressionMethod (Maybe ExtensionList)
	| ServerHelloRaw ByteString
	deriving Show

instance Parsable ServerHello where
	parse = parseServerHello
	toByteString = serverHelloToByteString
	listLength _ = Nothing

serverHelloServerRandom :: ServerHello -> Maybe Random
serverHelloServerRandom (ServerHello _ r _ _ _ _) = Just r
serverHelloServerRandom _ = Nothing

serverHelloServerVersion :: ServerHello -> Maybe Version
serverHelloServerVersion (ServerHello v _ _ _ _ _) = Just v
serverHelloServerVersion _ = Nothing

serverHelloCipherSuite :: ServerHello -> Maybe CipherSuite
serverHelloCipherSuite (ServerHello _ _ _ cs _ _) = Just cs
serverHelloCipherSuite _ = Nothing

parseServerHello :: ByteStringM ServerHello
parseServerHello = do
	(pv, r, sid) <- getPvRSid
	cs <- parse
	cm <- parseCompressionMethod
	e <- emptyBS
	me <- if e then return Nothing else Just <$> parseExtensionList
	return $ ServerHello pv r sid cs cm me

serverHelloToByteString :: ServerHello -> ByteString
serverHelloToByteString (ServerHello pv r sid cs cm mes) = BS.concat [
	toByteString pv,
	toByteString r,
	sessionIdToByteString sid,
	toByteString cs,
	compressionMethodToByteString cm,
	maybe "" extensionListToByteString mes
 ]
serverHelloToByteString (ServerHelloRaw sh) = sh

data CompressionMethod
	= CompressionMethodNull
	| CompressionMethodRaw Word8
	deriving Show

instance Parsable CompressionMethod where
	parse = parseCompressionMethod
	toByteString = compressionMethodToByteString
	listLength _ = Just 1

parseCompressionMethod :: ByteStringM CompressionMethod
parseCompressionMethod = do
	cm <- headBS
	return $ case cm of
		0 -> CompressionMethodNull
		_ -> CompressionMethodRaw cm

compressionMethodToByteString :: CompressionMethod -> ByteString
compressionMethodToByteString CompressionMethodNull = "\0"
compressionMethodToByteString (CompressionMethodRaw cm) = pack [cm]

data SessionId = SessionId ByteString

instance Show SessionId where
	show (SessionId sid) =
		"(SessionID " ++ concatMap (`showHex` "") (unpack sid) ++ ")"

parseSessionId :: ByteStringM SessionId
parseSessionId = SessionId <$> takeLen 1

sessionIdToByteString :: SessionId -> ByteString
sessionIdToByteString (SessionId sid) = lenBodyToByteString 1 sid
