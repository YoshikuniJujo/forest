{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Parts (
	Version(..), Parsable(..), Random(..), CipherSuite(..),
	HashAlgorithm(..), SignatureAlgorithm(..),

	Parsable'(..),

--	list1,
	whole, ByteStringM, evalByteStringM, headBS,

	lenBodyToByteString, emptyBS, concat,

	byteStringToInt, intToByteString,
	section, takeWords, takeLen, takeBS,

	takeLen',

	NamedCurve(..),
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

parseCipherSuite' :: Monad m => (Int -> m BS.ByteString) -> m CipherSuite
parseCipherSuite' rd = do
	[w1, w2] <- takeWords' rd 2
	return $ case (w1, w2) of
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

instance Parsable' CipherSuite where
	parse' = parseCipherSuite'

cipherSuiteToByteString :: CipherSuite -> ByteString
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
cipherSuiteToByteString (CipherSuiteRaw w1 w2) = pack [w1, w2]
cipherSuiteToByteString _ = error "cannot identified"

parseVersion :: ByteStringM Version
parseVersion = do
	[vmjr, vmnr] <- takeWords 2
	return $ Version vmjr vmnr

instance Parsable' Version where
	parse' rd = do
		[vmjr, vmnr] <- takeWords' rd 2
		return $ Version vmjr vmnr

instance Parsable NamedCurve where
	parse = parseNamedCurve
	toByteString = namedCurveToByteString
	listLength _ = Nothing

parseNamedCurve :: ByteStringM NamedCurve
parseNamedCurve = do
	nc <- takeWord16
	return $ case nc of
		23 -> Secp256r1
		24 -> Secp384r1
		25 -> Secp521r1
		_ -> NamedCurveRaw nc

namedCurveToByteString :: NamedCurve -> ByteString
namedCurveToByteString (Secp256r1) = word16ToByteString 23
namedCurveToByteString (Secp384r1) = word16ToByteString 24
namedCurveToByteString (Secp521r1) = word16ToByteString 25
namedCurveToByteString (NamedCurveRaw nc) = word16ToByteString nc

instance Parsable Version where
	parse = parseVersion
	toByteString = versionToByteString
	listLength _ = Nothing
