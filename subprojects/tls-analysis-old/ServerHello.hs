{-# LANGUAGE OverloadedStrings #-}

module ServerHello (
	ServerHello(..), parseServerHello, serverHelloToByteString,
	serverHelloServerRandom, serverHelloCipherSuite,
	serverHelloServerVersion,
) where

import Prelude hiding (concat)

import Control.Applicative ((<$>))

import Parts
import Extension
import ByteStringMonad
-- import ToByteString

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
	e <- empty
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
