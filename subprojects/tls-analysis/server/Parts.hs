{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Parts (
	Version(..), Parsable(..), Random(..), CipherSuite(..),
	HashAlgorithm(..), SignatureAlgorithm(..),
	parseSignatureAlgorithm,

	Parsable'(..),

--	list1,
	whole, ByteStringM, evalByteStringM, headBS,

	lenBodyToByteString, emptyBS, concat,

	byteStringToInt, intToByteString,
	section, takeWords, takeLen, takeBS,

	takeLen',
) where

import Prelude hiding (head, take, concat)
import qualified Prelude
import Numeric

import Control.Applicative ((<$>))
import Control.Monad

import qualified Data.ByteString as BS

import Types
import ByteStringMonad
-- import ToByteString

instance Show Random where
	show (Random r) =
		"(Random " ++ concatMap (`showHex` "") (unpack r) ++ ")"

instance Parsable Random where
	parse = parseRandom
	toByteString = randomToByteString
	listLength _ = Nothing

parseRandom :: ByteStringM Random
parseRandom = Random <$> takeBS 32

instance Parsable' Random where
	parse' rd = Random `liftM` rd 32

randomToByteString :: Random -> ByteString
randomToByteString (Random r) = r

instance Parsable CipherSuite where
	parse = parseCipherSuite
	toByteString = cipherSuiteToByteString
	listLength _ = Just 2

parseCipherSuite :: ByteStringM CipherSuite
parseCipherSuite = do
	[w1, w2] <- takeWords 2
	return $ case (w1, w2) of
		(0x00, 0x00) -> TLS_NULL_WITH_NULL_NULL
		(0x00, 0x2f) -> TLS_RSA_WITH_AES_128_CBC_SHA
		(0x00, 0x33) -> TLS_DHE_RSA_WITH_AES_128_CBC_SHA
		(0x00, 0x39) -> TLS_ECDHE_PSK_WITH_NULL_SHA
		(0x00, 0x3c) -> TLS_RSA_WITH_AES_128_CBC_SHA256
		(0x00, 0x45) -> TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
		_ -> CipherSuiteRaw w1 w2

parseCipherSuite' :: Monad m => (Int -> m BS.ByteString) -> m CipherSuite
parseCipherSuite' rd = do
	[w1, w2] <- takeWords' rd 2
	return $ case (w1, w2) of
		(0x00, 0x00) -> TLS_NULL_WITH_NULL_NULL
		(0x00, 0x2f) -> TLS_RSA_WITH_AES_128_CBC_SHA
		(0x00, 0x33) -> TLS_DHE_RSA_WITH_AES_128_CBC_SHA
		(0x00, 0x39) -> TLS_ECDHE_PSK_WITH_NULL_SHA
		(0x00, 0x3c) -> TLS_RSA_WITH_AES_128_CBC_SHA256
		(0x00, 0x45) -> TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
		_ -> CipherSuiteRaw w1 w2

instance Parsable' CipherSuite where
	parse' = parseCipherSuite'

cipherSuiteToByteString :: CipherSuite -> ByteString
cipherSuiteToByteString TLS_NULL_WITH_NULL_NULL = "\x00\x00"
cipherSuiteToByteString TLS_RSA_WITH_AES_128_CBC_SHA = "\x00\x2f"
cipherSuiteToByteString TLS_DHE_RSA_WITH_AES_128_CBC_SHA = "\x00\x33"
cipherSuiteToByteString TLS_ECDHE_PSK_WITH_NULL_SHA = "\x00\x39"
cipherSuiteToByteString TLS_RSA_WITH_AES_128_CBC_SHA256 = "\x00\x3c"
cipherSuiteToByteString TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = "\x00\x45"
cipherSuiteToByteString (CipherSuiteRaw w1 w2) = pack [w1, w2]

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

data SignatureAlgorithm
	= SignatureAlgorithmRsa
	| SignatureAlgorithmDsa
	| SignatureAlgorithmRaw Word8
	deriving Show

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
		_ -> SignatureAlgorithmRaw sa

signatureAlgorithmToByteString :: SignatureAlgorithm -> ByteString
signatureAlgorithmToByteString SignatureAlgorithmRsa = "\x01"
signatureAlgorithmToByteString SignatureAlgorithmDsa = "\x02"
signatureAlgorithmToByteString (SignatureAlgorithmRaw w) = pack [w]

instance Parsable Version where
	parse = parseVersion
	toByteString = versionToByteString
	listLength _ = Nothing

parseVersion :: ByteStringM Version
parseVersion = do
	[vmjr, vmnr] <- takeWords 2
	return $ Version vmjr vmnr

instance Parsable' Version where
	parse' rd = do
		[vmjr, vmnr] <- takeWords' rd 2
		return $ Version vmjr vmnr
