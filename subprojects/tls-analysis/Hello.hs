{-# LANGUAGE OverloadedStrings #-}

module Hello (
	clientHelloToByteString, clientHelloOnlyKnownCipherSuite, parseClientHello,
	CipherSuite(..), ProtocolVersion(..), Random(..), ClientHello(..),
	clientHelloClientRandom, clientHelloClientVersion,
	SignatureAlgorithm(..), HashAlgorithm(..), CompressionMethod(..),
	SessionId(..), Version(..), fst3, fromInt,

	serverHelloToByteString, parseServerHello, ServerHello(..),
	serverHelloServerRandom, serverHelloServerVersion, serverHelloCipherSuite,
 ) where

import Prelude hiding (concat, take)
import Numeric

import Control.Applicative
import Data.ByteString (ByteString, pack, unpack)
import Data.Word

import Types

import Parts(
--	ProtocolVersion(..), parseProtocolVersion, protocolVersionToByteString,

	CipherSuite(..), parseCipherSuite, parseCipherSuiteList,
	cipherSuiteListToByteString, cipherSuiteToByteString,

	Random(..), parseRandom, randomToByteString,

	SignatureAlgorithm(..),
	HashAlgorithm(..),
	Version(..),

	fst3, fromInt,
	section, list1, lenBodyToByteString, headBS, takeLen, )
import Extension

data ClientHello
	= ClientHello ProtocolVersion Random SessionId [CipherSuite]
		[CompressionMethod] (Maybe ExtensionList)
	| ClientHelloRaw ByteString
	deriving Show

clientHelloOnlyKnownCipherSuite :: ClientHello -> ClientHello
clientHelloOnlyKnownCipherSuite (ClientHello pv r sid css cms mel) =
	ClientHello pv r sid (TLS_RSA_WITH_AES_128_CBC_SHA : css) cms mel
clientHelloOnlyKnownCipherSuite ch = ch

clientHelloClientRandom :: ClientHello -> Maybe Random
clientHelloClientRandom (ClientHello _ r _ _ _ _) = Just r
clientHelloClientRandom _ = Nothing

clientHelloClientVersion :: ClientHello -> Maybe ProtocolVersion
clientHelloClientVersion (ClientHello v _ _ _ _ _) = Just v
clientHelloClientVersion _ = Nothing

parseClientHello :: ByteStringM ClientHello
parseClientHello = do
	pv <- parseProtocolVersion
	r <- parseRandom
	sid <- parseSessionId
	css <- parseCipherSuiteList
	cms <- parseCompressionMethodList
	e <- emptyBS
	mel <- if e then return Nothing else Just <$> parseExtensionList
	return $ ClientHello pv r sid css cms mel

clientHelloToByteString :: ClientHello -> ByteString
clientHelloToByteString (ClientHello pv r sid css cms mel) = concat [
	protocolVersionToByteString pv,
	randomToByteString r,
	sessionIdToByteString sid,
	cipherSuiteListToByteString css,
	compressionMethodListToByteString cms,
	maybe "" extensionListToByteString mel
 ]
clientHelloToByteString (ClientHelloRaw bs) = bs

data ServerHello
	= ServerHello ProtocolVersion Random SessionId CipherSuite
		CompressionMethod (Maybe ExtensionList)
	| ServerHelloRaw ByteString
	deriving Show

serverHelloServerRandom :: ServerHello -> Maybe Random
serverHelloServerRandom (ServerHello _ r _ _ _ _) = Just r
serverHelloServerRandom _ = Nothing

serverHelloServerVersion :: ServerHello -> Maybe ProtocolVersion
serverHelloServerVersion (ServerHello v _ _ _ _ _) = Just v
serverHelloServerVersion _ = Nothing

serverHelloCipherSuite :: ServerHello -> Maybe CipherSuite
serverHelloCipherSuite (ServerHello _ _ _ cs _ _) = Just cs
serverHelloCipherSuite _ = Nothing

parseServerHello :: ByteStringM ServerHello
parseServerHello = do
	pv <- parseProtocolVersion
	r <- parseRandom
	sid <- parseSessionId
	cs <- parseCipherSuite
	cm <- parseCompressionMethod
	e <- emptyBS
	me <- if e then return Nothing else Just <$> parseExtensionList
	return $ ServerHello pv r sid cs cm me

serverHelloToByteString :: ServerHello -> ByteString
serverHelloToByteString (ServerHello pv r sid cs cm mes) = concat [
	protocolVersionToByteString pv,
	randomToByteString r,
	sessionIdToByteString sid,
	cipherSuiteToByteString cs,
	compressionMethodToByteString cm,
	maybe "" extensionListToByteString mes
 ]
serverHelloToByteString (ServerHelloRaw sh) = sh

data CompressionMethod
	= CompressionMethodNull
	| CompressionMethodRaw Word8
	deriving Show

parseCompressionMethodList :: ByteStringM [CompressionMethod]
parseCompressionMethodList = section 1 $ list1 parseCompressionMethod

compressionMethodListToByteString :: [CompressionMethod] -> ByteString
compressionMethodListToByteString =
	lenBodyToByteString 1 . concat . map compressionMethodToByteString

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
