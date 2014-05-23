{-# LANGUAGE OverloadedStrings #-}

module Types (
	Fragment(..),
	Version(..), byteStringToVersion, versionToByteString,
	ContentType(..), byteStringToContentType, contentTypeToByteString,
	Random(..), CipherSuite(..),
) where

import Data.Word
import qualified Data.ByteString as BS

data Fragment
	= Fragment ContentType Version BS.ByteString
	deriving Show

data Version
	= Version Word8 Word8
	deriving (Show, Eq, Ord)

byteStringToVersion :: BS.ByteString -> Version
byteStringToVersion v = let [vmjr, vmnr] = BS.unpack v in Version vmjr vmnr

versionToByteString :: Version -> BS.ByteString
versionToByteString (Version vmjr vmnr) = BS.pack [vmjr, vmnr]

data ContentType
	= ContentTypeChangeCipherSpec
	| ContentTypeAlert
	| ContentTypeHandshake
	| ContentTypeApplicationData
	| ContentTypeRaw Word8
	deriving Show

byteStringToContentType :: BS.ByteString -> ContentType
byteStringToContentType "\20" = ContentTypeChangeCipherSpec
byteStringToContentType "\21" = ContentTypeAlert
byteStringToContentType "\22" = ContentTypeHandshake
byteStringToContentType "\23" = ContentTypeApplicationData
byteStringToContentType bs = let [ct] = BS.unpack bs in ContentTypeRaw ct

contentTypeToByteString :: ContentType -> BS.ByteString
contentTypeToByteString ContentTypeChangeCipherSpec = BS.pack [20]
contentTypeToByteString ContentTypeAlert = BS.pack [21]
contentTypeToByteString ContentTypeHandshake = BS.pack [22]
contentTypeToByteString ContentTypeApplicationData = BS.pack [23]
contentTypeToByteString (ContentTypeRaw ct) = BS.pack [ct]

data Random = Random BS.ByteString

data CipherSuite
	= TLS_NULL_WITH_NULL_NULL
	| TLS_RSA_WITH_AES_128_CBC_SHA
	| TLS_DHE_RSA_WITH_AES_128_CBC_SHA
	| TLS_ECDHE_PSK_WITH_NULL_SHA
	| TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
	| CipherSuiteRaw Word8 Word8
	deriving (Show, Eq)
