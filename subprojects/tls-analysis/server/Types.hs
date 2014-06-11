{-# LANGUAGE OverloadedStrings, PackageImports, ScopedTypeVariables,
	FlexibleInstances, TypeFamilies, TupleSections #-}

module Types (
	Version(..), byteStringToVersion, versionToByteString,
	ContentType(..), byteStringToContentType, contentTypeToByteString,
	Random(..), CipherSuite(..), CipherSuiteKeyEx(..), CipherSuiteMsgEnc(..),

	NamedCurve(..),

	SignatureAlgorithm(..), HashAlgorithm(..),

	lenBodyToByteString,

	takeLen,
) where

import Data.Word
import qualified Data.ByteString as BS

import Prelude hiding (head, take)
import qualified Prelude

import Data.Bits
import Data.ByteString (ByteString)
import "monads-tf" Control.Monad.State

import Numeric

import qualified Codec.Bytable as B
import Codec.Bytable.BigEndian ()

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

instance B.Bytable HashAlgorithm where
	fromByteString = byteStringToHashAlgorithm
	toByteString = hashAlgorithmToByteString

byteStringToHashAlgorithm :: BS.ByteString -> Either String HashAlgorithm
byteStringToHashAlgorithm bs = case BS.unpack bs of
	[ha] -> Right $ case ha of
		2 -> HashAlgorithmSha1
		3 -> HashAlgorithmSha224
		4 -> HashAlgorithmSha256
		5 -> HashAlgorithmSha384
		6 -> HashAlgorithmSha512
		_ -> HashAlgorithmRaw ha
	_ -> Left "Type.byteStringToHashAlgorithm"

hashAlgorithmToByteString :: HashAlgorithm -> ByteString
hashAlgorithmToByteString HashAlgorithmSha1 = "\x02"
hashAlgorithmToByteString HashAlgorithmSha224 = "\x03"
hashAlgorithmToByteString HashAlgorithmSha256 = "\x04"
hashAlgorithmToByteString HashAlgorithmSha384 = "\x05"
hashAlgorithmToByteString HashAlgorithmSha512 = "\x06"
hashAlgorithmToByteString (HashAlgorithmRaw w) = BS.pack [w]

instance B.Bytable SignatureAlgorithm where
	fromByteString = byteStringToSignatureAlgorithm
	toByteString = signatureAlgorithmToByteString

byteStringToSignatureAlgorithm :: BS.ByteString -> Either String SignatureAlgorithm
byteStringToSignatureAlgorithm bs = case BS.unpack bs of
	[sa] -> Right $ case sa of
		1 -> SignatureAlgorithmRsa
		2 -> SignatureAlgorithmDsa
		3 -> SignatureAlgorithmEcdsa
		_ -> SignatureAlgorithmRaw sa
	_ -> Left "Type.byteStringToSignatureAlgorithm"

signatureAlgorithmToByteString :: SignatureAlgorithm -> ByteString
signatureAlgorithmToByteString SignatureAlgorithmRsa = "\x01"
signatureAlgorithmToByteString SignatureAlgorithmDsa = "\x02"
signatureAlgorithmToByteString SignatureAlgorithmEcdsa = "\x03"
signatureAlgorithmToByteString (SignatureAlgorithmRaw w) = BS.pack [w]

instance B.Bytable NamedCurve where
	fromByteString = byteStringToNamedCurve
	toByteString = namedCurveToByteString

byteStringToNamedCurve :: ByteString -> Either String NamedCurve
byteStringToNamedCurve bs = case BS.unpack bs of
	[w1, w2] -> Right $ case fromIntegral w1 `shiftL` 8 .|. fromIntegral w2 of
		23 -> Secp256r1
		24 -> Secp384r1
		25 -> Secp521r1
		nc -> NamedCurveRaw nc
	_ -> Left "Types.byteStringToNamedCurve"

namedCurveToByteString :: NamedCurve -> ByteString
namedCurveToByteString (Secp256r1) = word16ToByteString 23
namedCurveToByteString (Secp384r1) = word16ToByteString 24
namedCurveToByteString (Secp521r1) = word16ToByteString 25
namedCurveToByteString (NamedCurveRaw nc) = word16ToByteString nc

takeInt :: Monad m => (Int -> m BS.ByteString) -> Int -> m Int
takeInt rd = (byteStringToInt `liftM`) . rd

takeLen :: Monad m => (Int -> m BS.ByteString) -> Int -> m ByteString
takeLen rd n = do
	l <- takeInt rd n
	rd l

word16ToByteString :: Word16 -> ByteString
word16ToByteString w = BS.pack [fromIntegral (w `shiftR` 8), fromIntegral w]

byteStringToInt :: ByteString -> Int
byteStringToInt bs = wordsToInt (BS.length bs - 1) $ BS.unpack bs

wordsToInt :: Int -> [Word8] -> Int
wordsToInt n _ | n < 0 = 0
wordsToInt _ [] = 0
wordsToInt n (x : xs) = fromIntegral x `shift` (n * 8) .|. wordsToInt (n - 1) xs

intToByteString :: Int -> Int -> ByteString
intToByteString n = BS.pack . reverse . intToWords n

intToWords :: Int -> Int -> [Word8]
intToWords 0 _ = []
intToWords n i = fromIntegral i : intToWords (n - 1) (i `shiftR` 8)

lenBodyToByteString :: Int -> ByteString -> ByteString
lenBodyToByteString n bs = intToByteString n (BS.length bs) `BS.append` bs

instance Show Random where
	show (Random r) =
		"(Random " ++ concatMap (`showHex` "") (BS.unpack r) ++ ")"

instance B.Bytable Random where
	fromByteString = Right . Random
	toByteString (Random bs) = bs

byteStringToCipherSuite :: BS.ByteString -> Either String CipherSuite
byteStringToCipherSuite bs = case BS.unpack bs of
	[w1, w2] -> Right $ case (w1, w2) of
		(0x00, 0x00) -> CipherSuite KeyExNULL MsgEncNULL
		(0x00, 0x2f) -> CipherSuite RSA AES_128_CBC_SHA
		(0x00, 0x33) -> CipherSuite DHE_RSA AES_128_CBC_SHA
		(0x00, 0x39) -> CipherSuite ECDHE_PSK NULL_SHA
		(0x00, 0x3c) -> CipherSuite RSA AES_128_CBC_SHA256
		(0x00, 0x45) -> CipherSuite DHE_RSA CAMELLIA_128_CBC_SHA
		(0x00, 0x67) -> CipherSuite DHE_RSA AES_128_CBC_SHA256
		(0xc0, 0x09) -> CipherSuite ECDHE_ECDSA AES_128_CBC_SHA
		(0xc0, 0x13) -> CipherSuite ECDHE_RSA AES_128_CBC_SHA
		(0xc0, 0x23) -> CipherSuite ECDHE_ECDSA AES_128_CBC_SHA256
		(0xc0, 0x27) -> CipherSuite ECDHE_RSA AES_128_CBC_SHA256
		_ -> CipherSuiteRaw w1 w2
	_ -> Left "Types.byteStringToCipherSuite"

instance B.Bytable CipherSuite where
	fromByteString = byteStringToCipherSuite
	toByteString = cipherSuiteToByteString

cipherSuiteToByteString :: CipherSuite -> BS.ByteString
cipherSuiteToByteString (CipherSuite KeyExNULL MsgEncNULL) = "\x00\x00"
cipherSuiteToByteString (CipherSuite RSA AES_128_CBC_SHA) = "\x00\x2f"
cipherSuiteToByteString (CipherSuite DHE_RSA AES_128_CBC_SHA) = "\x00\x33"
cipherSuiteToByteString (CipherSuite ECDHE_PSK NULL_SHA) = "\x00\x39"
cipherSuiteToByteString (CipherSuite RSA AES_128_CBC_SHA256) = "\x00\x3c"
cipherSuiteToByteString (CipherSuite DHE_RSA CAMELLIA_128_CBC_SHA) = "\x00\x45"
cipherSuiteToByteString (CipherSuite DHE_RSA AES_128_CBC_SHA256) = "\x00\x67"
cipherSuiteToByteString (CipherSuite ECDHE_ECDSA AES_128_CBC_SHA) = "\xc0\x09"
cipherSuiteToByteString (CipherSuite ECDHE_RSA AES_128_CBC_SHA) = "\xc0\x13"
cipherSuiteToByteString (CipherSuite ECDHE_ECDSA AES_128_CBC_SHA256) = "\xc0\x23"
cipherSuiteToByteString (CipherSuite ECDHE_RSA AES_128_CBC_SHA256) = "\xc0\x27"
cipherSuiteToByteString (CipherSuiteRaw w1 w2) = BS.pack [w1, w2]
cipherSuiteToByteString _ = error "cannot identified"

instance B.Bytable Version where
	fromByteString bs = case BS.unpack bs of
		[vmjr, vmnr] -> Right $ Version vmjr vmnr
		_ -> Left "Types.hs: B.Bytable Version"
	toByteString (Version vmjr vmnr) = BS.pack [vmjr, vmnr]
