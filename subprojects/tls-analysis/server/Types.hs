{-# LANGUAGE OverloadedStrings #-}

module Types (
	Fragment(..),
	Version(..), byteStringToVersion, versionToByteString,
	ContentType(..), byteStringToContentType, contentTypeToByteString,
	Random(..), CipherSuite(..), CipherSuiteKeyEx(..), CipherSuiteMsgEnc(..),

	NamedCurve(..),

	SignatureAlgorithm(..),
	HashAlgorithm(..),
	Parsable(..),
) where

import Data.Word
import qualified Data.ByteString as BS
import ByteStringMonad

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
	deriving (Show, Eq)

byteStringToContentType :: BS.ByteString -> ContentType
byteStringToContentType "" = error "Types.byteStringToContentType: empty"
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

data CipherSuiteKeyEx
	= RSA
	| DHE_RSA
	| ECDHE_RSA
	| ECDHE_ECDSA
	| ECDHE_PSK
	| KeyExNULL
	deriving (Show, Read, Eq)

data CipherSuiteMsgEnc
	= AES_128_CBC_SHA
	| AES_128_CBC_SHA256
	| CAMELLIA_128_CBC_SHA
	| NULL_SHA
	| MsgEncNULL
	deriving (Show, Read, Eq)

data CipherSuite
	= CipherSuite CipherSuiteKeyEx CipherSuiteMsgEnc
	| CipherSuiteRaw Word8 Word8
	deriving (Show, Read, Eq)

data NamedCurve
	= Secp256r1
	| Secp384r1
	| Secp521r1
	| NamedCurveRaw Word16
	deriving Show

data SignatureAlgorithm
	= SignatureAlgorithmRsa
	| SignatureAlgorithmDsa
	| SignatureAlgorithmEcdsa
	| SignatureAlgorithmRaw Word8
	deriving Show

data HashAlgorithm
	= HashAlgorithmSha1
	| HashAlgorithmSha224
	| HashAlgorithmSha256
	| HashAlgorithmSha384
	| HashAlgorithmSha512
	| HashAlgorithmRaw Word8
	deriving Show

instance Parsable HashAlgorithm where
	parse = parseHashAlgorithm
	toByteString = hashAlgorithmToByteString
	listLength _ = Just 1

parseHashAlgorithm :: ByteStringM HashAlgorithm
parseHashAlgorithm = do
	ha <- headBS
	return $ case ha of
		2 -> HashAlgorithmSha1
		3 -> HashAlgorithmSha224
		4 -> HashAlgorithmSha256
		5 -> HashAlgorithmSha384
		6 -> HashAlgorithmSha512
		_ -> HashAlgorithmRaw ha

hashAlgorithmToByteString :: HashAlgorithm -> ByteString
hashAlgorithmToByteString HashAlgorithmSha1 = "\x02"
hashAlgorithmToByteString HashAlgorithmSha224 = "\x03"
hashAlgorithmToByteString HashAlgorithmSha256 = "\x04"
hashAlgorithmToByteString HashAlgorithmSha384 = "\x05"
hashAlgorithmToByteString HashAlgorithmSha512 = "\x06"
hashAlgorithmToByteString (HashAlgorithmRaw w) = pack [w]

instance Parsable SignatureAlgorithm where
	parse = parseSignatureAlgorithm
	toByteString = signatureAlgorithmToByteString
	listLength _ = Just 1

parseSignatureAlgorithm :: ByteStringM SignatureAlgorithm
parseSignatureAlgorithm = do
	sa <- headBS
	return $ case sa of
		1 -> SignatureAlgorithmRsa
		2 -> SignatureAlgorithmDsa
		3 -> SignatureAlgorithmEcdsa
		_ -> SignatureAlgorithmRaw sa

signatureAlgorithmToByteString :: SignatureAlgorithm -> ByteString
signatureAlgorithmToByteString SignatureAlgorithmRsa = "\x01"
signatureAlgorithmToByteString SignatureAlgorithmDsa = "\x02"
signatureAlgorithmToByteString SignatureAlgorithmEcdsa = "\x03"
signatureAlgorithmToByteString (SignatureAlgorithmRaw w) = pack [w]
