{-# LANGUAGE OverloadedStrings #-}

module Parts (
	ProtocolVersion(..), parseProtocolVersion, protocolVersionToByteString,
	Random(..), parseRandom, randomToByteString,
	SessionId, parseSessionId, sessionIdToByteString,
	CipherSuite(..), parseCipherSuite, cipherSuiteToByteString,
		parseCipherSuiteList, cipherSuiteListToByteString,
	CompressionMethod, parseCompressionMethod, compressionMethodToByteString,
		parseCompressionMethodList, compressionMethodListToByteString,
	ContentType(..), byteStringToContentType, contentTypeToByteString,
	Version, byteStringToVersion, versionToByteString,
) where

import Prelude hiding (head, take, concat)
import Numeric

import Control.Applicative ((<$>))

import ByteStringMonad
import ToByteString

data ProtocolVersion = ProtocolVersion Word8 Word8 deriving Show

parseProtocolVersion :: ByteStringM ProtocolVersion
parseProtocolVersion = do
	[vmjr, vmnr] <- takeWords 2
	return $ ProtocolVersion vmjr vmnr

protocolVersionToByteString :: ProtocolVersion -> ByteString
protocolVersionToByteString (ProtocolVersion vmjr vmnr) = pack [vmjr, vmnr]

data Random = Random ByteString

instance Show Random where
	show (Random r) =
		"(Random " ++ concatMap (`showHex` "") (unpack r) ++ ")"

parseRandom :: ByteStringM Random
parseRandom = Random <$> take 32

randomToByteString :: Random -> ByteString
randomToByteString (Random r) = r

data SessionId = SessionId ByteString

instance Show SessionId where
	show (SessionId sid) =
		"(SessionID " ++ concatMap (`showHex` "") (unpack sid) ++ ")"

parseSessionId :: ByteStringM SessionId
parseSessionId = SessionId <$> takeLen 1

sessionIdToByteString :: SessionId -> ByteString
sessionIdToByteString (SessionId sid) = lenBodyToByteString 1 sid

data CipherSuite
	= TLS_NULL_WITH_NULL_NULL
	| TLS_RSA_WITH_AES_128_CBC_SHA
	| CipherSuiteRaw Word8 Word8
	deriving Show

parseCipherSuiteList :: ByteStringM [CipherSuite]
parseCipherSuiteList = section 2 $ list1 parseCipherSuite

cipherSuiteListToByteString :: [CipherSuite] -> ByteString
cipherSuiteListToByteString =
	lenBodyToByteString 2 . concat . map cipherSuiteToByteString

parseCipherSuite :: ByteStringM CipherSuite
parseCipherSuite = do
	[w1, w2] <- takeWords 2
	return $ case (w1, w2) of
		(0x00, 0x00) -> TLS_NULL_WITH_NULL_NULL
		(0x00, 0x2f) -> TLS_RSA_WITH_AES_128_CBC_SHA
		_ -> CipherSuiteRaw w1 w2

cipherSuiteToByteString :: CipherSuite -> ByteString
cipherSuiteToByteString TLS_NULL_WITH_NULL_NULL = "\x00\x00"
cipherSuiteToByteString TLS_RSA_WITH_AES_128_CBC_SHA = "\x00\x2f"
cipherSuiteToByteString (CipherSuiteRaw w1 w2) = pack [w1, w2]

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
	cm <- head
	return $ case cm of
		0 -> CompressionMethodNull
		_ -> CompressionMethodRaw cm

compressionMethodToByteString :: CompressionMethod -> ByteString
compressionMethodToByteString CompressionMethodNull = "\0"
compressionMethodToByteString (CompressionMethodRaw cm) = pack [cm]

data ContentType
	= ContentTypeChangeCipherSpec
	| ContentTypeHandshake
	| ContentTypeRaw Word8
	deriving Show

byteStringToContentType :: ByteString -> ContentType
byteStringToContentType "\20" = ContentTypeChangeCipherSpec
byteStringToContentType "\22" = ContentTypeHandshake
byteStringToContentType bs = let [ct] = unpack bs in ContentTypeRaw ct

contentTypeToByteString :: ContentType -> ByteString
contentTypeToByteString ContentTypeChangeCipherSpec = pack [20]
contentTypeToByteString ContentTypeHandshake = pack [22]
contentTypeToByteString (ContentTypeRaw ct) = pack [ct]

data Version
	= Version Word8 Word8
	deriving Show

byteStringToVersion :: ByteString -> Version
byteStringToVersion v = let [vmjr, vmnr] = unpack v in Version vmjr vmnr

versionToByteString :: Version -> ByteString
versionToByteString (Version vmjr vmnr) = pack [vmjr, vmnr]
