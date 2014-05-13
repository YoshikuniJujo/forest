{-# LANGUAGE OverloadedStrings #-}

module Parts (
--	ProtocolVersion(..), parseProtocolVersion, protocolVersionToByteString,
	Random(..), parseRandom, randomToByteString,
	CipherSuite(..), parseCipherSuite, cipherSuiteToByteString,
		parseCipherSuiteList, cipherSuiteListToByteString,
	ContentType(..), byteStringToContentType, contentTypeToByteString,
	Version(..), byteStringToVersion, versionToByteString,
	HashAlgorithm(..), parseHashAlgorithm, hashAlgorithmToByteString,
	SignatureAlgorithm(..), parseSignatureAlgorithm,
	signatureAlgorithmToByteString,
	hashSignatureAlgorithmToByteString,
	parseHashSignatureAlgorithm,

	list1, whole, ByteStringM, evalByteStringM, headBS,

	word64ToByteString, lenBodyToByteString, emptyBS, concat,

	fst3, fromInt,

	byteStringToInt, intToByteString, showKeySingle, showKey,
	section, takeWords, takeLen, take,
) where

import Prelude hiding (head, take, concat)
import Numeric

import Control.Applicative ((<$>), (<*>))
import qualified Data.ByteString as BS

import ByteStringMonad
-- import ToByteString

data Random = Random ByteString

instance Show Random where
	show (Random r) =
		"(Random " ++ concatMap (`showHex` "") (unpack r) ++ ")"

parseRandom :: ByteStringM Random
parseRandom = Random <$> take 32

randomToByteString :: Random -> ByteString
randomToByteString (Random r) = r

data CipherSuite
	= TLS_NULL_WITH_NULL_NULL
	| TLS_RSA_WITH_AES_128_CBC_SHA
	| TLS_DHE_RSA_WITH_AES_128_CBC_SHA
	| TLS_ECDHE_PSK_WITH_NULL_SHA
	| TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
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
		(0x00, 0x33) -> TLS_DHE_RSA_WITH_AES_128_CBC_SHA
		(0x00, 0x39) -> TLS_ECDHE_PSK_WITH_NULL_SHA
		(0x00, 0x45) -> TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
		_ -> CipherSuiteRaw w1 w2

cipherSuiteToByteString :: CipherSuite -> ByteString
cipherSuiteToByteString TLS_NULL_WITH_NULL_NULL = "\x00\x00"
cipherSuiteToByteString TLS_RSA_WITH_AES_128_CBC_SHA = "\x00\x2f"
cipherSuiteToByteString TLS_DHE_RSA_WITH_AES_128_CBC_SHA = "\x00\x33"
cipherSuiteToByteString TLS_ECDHE_PSK_WITH_NULL_SHA = "\x00\x39"
cipherSuiteToByteString TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = "\x00\x45"
cipherSuiteToByteString (CipherSuiteRaw w1 w2) = pack [w1, w2]

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

data Version
	= Version Word8 Word8
	deriving Show

byteStringToVersion :: ByteString -> Version
byteStringToVersion v = let [vmjr, vmnr] = unpack v in Version vmjr vmnr

versionToByteString :: Version -> ByteString
versionToByteString (Version vmjr vmnr) = pack [vmjr, vmnr]

data HashAlgorithm
	= HashAlgorithmSha1
	| HashAlgorithmSha224
	| HashAlgorithmSha256
	| HashAlgorithmSha384
	| HashAlgorithmSha512
	| HashAlgorithmRaw Word8
	deriving Show

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

data SignatureAlgorithm
	= SignatureAlgorithmRsa
	| SignatureAlgorithmDsa
	| SignatureAlgorithmRaw Word8
	deriving Show

parseSignatureAlgorithm :: ByteStringM SignatureAlgorithm
parseSignatureAlgorithm = do
	sa <- headBS
	return $ case sa of
		1 -> SignatureAlgorithmRsa
		2 -> SignatureAlgorithmDsa
		_ -> SignatureAlgorithmRaw sa

signatureAlgorithmToByteString :: SignatureAlgorithm -> ByteString
signatureAlgorithmToByteString SignatureAlgorithmRsa = "\x01"
signatureAlgorithmToByteString SignatureAlgorithmDsa = "\x02"
signatureAlgorithmToByteString (SignatureAlgorithmRaw w) = pack [w]

hashSignatureAlgorithmToByteString :: (HashAlgorithm, SignatureAlgorithm) -> ByteString
hashSignatureAlgorithmToByteString (ha, sa) = BS.concat [
	hashAlgorithmToByteString ha,
	signatureAlgorithmToByteString sa ]

parseHashSignatureAlgorithm :: ByteStringM (HashAlgorithm, SignatureAlgorithm)
parseHashSignatureAlgorithm =
	(,) <$> parseHashAlgorithm <*> parseSignatureAlgorithm
