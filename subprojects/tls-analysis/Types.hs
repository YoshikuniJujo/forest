{-# LANGUAGE OverloadedStrings #-}

module Types (
	Version(..), byteStringToVersion, versionToByteString,
	ContentType(..), byteStringToContentType, contentTypeToByteString,
) where

import Data.Word
import Data.ByteString (ByteString, pack, unpack)

data Version
	= Version Word8 Word8
	deriving Show

byteStringToVersion :: ByteString -> Version
byteStringToVersion v = let [vmjr, vmnr] = unpack v in Version vmjr vmnr

versionToByteString :: Version -> ByteString
versionToByteString (Version vmjr vmnr) = pack [vmjr, vmnr]

data ContentType
	= ContentTypeChangeCipherSpec
	| ContentTypeHandshake
	| ContentTypeApplicationData
	| ContentTypeRaw Word8
	deriving Show

byteStringToContentType :: ByteString -> ContentType
byteStringToContentType "\20" = ContentTypeChangeCipherSpec
byteStringToContentType "\22" = ContentTypeHandshake
byteStringToContentType "\23" = ContentTypeApplicationData
byteStringToContentType bs = let [ct] = unpack bs in ContentTypeRaw ct

contentTypeToByteString :: ContentType -> ByteString
contentTypeToByteString ContentTypeChangeCipherSpec = pack [20]
contentTypeToByteString ContentTypeHandshake = pack [22]
contentTypeToByteString ContentTypeApplicationData = pack [23]
contentTypeToByteString (ContentTypeRaw ct) = pack [ct]
