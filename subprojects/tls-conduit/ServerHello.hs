{-# LANGUAGE OverloadedStrings #-}

module ServerHello (ServerHello, parseServerHello, serverHelloToByteString) where

import Prelude hiding (concat)

import Control.Applicative ((<$>))

import Parts
import Extension
import ByteStringMonad
import ToByteString

data ServerHello
	= ServerHello ProtocolVersion Random SessionId CipherSuite
		CompressionMethod (Maybe ExtensionList)
	| ServerHelloRaw ByteString
	deriving Show

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
