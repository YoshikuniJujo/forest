{-# LANGUAGE OverloadedStrings #-}

module ClientHello (
	ClientHello(..), parseClientHello, clientHelloToByteString,
	clientHelloClientRandom,
) where

import Prelude hiding (concat)

import Control.Applicative ((<$>))

import Extension
import Parts
import ByteStringMonad

data ClientHello
	= ClientHello ProtocolVersion Random SessionId [CipherSuite]
		[CompressionMethod] (Maybe ExtensionList)
	| ClientHelloRaw ByteString
	deriving Show

clientHelloClientRandom :: ClientHello -> Maybe Random
clientHelloClientRandom (ClientHello _ r _ _ _ _) = Just r
clientHelloClientRandom _ = Nothing

parseClientHello :: ByteStringM ClientHello
parseClientHello = do
	pv <- parseProtocolVersion
	r <- parseRandom
	sid <- parseSessionId
	css <- parseCipherSuiteList
	cms <- parseCompressionMethodList
	e <- empty
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
