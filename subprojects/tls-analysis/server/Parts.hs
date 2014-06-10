{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Parts (
	Version(..), Parsable(..), Random(..),
	CipherSuite(..), CipherSuiteKeyEx(..), CipherSuiteMsgEnc(..),
	HashAlgorithm(..), SignatureAlgorithm(..),

	Parsable'(..),

--	list1,
	whole, ByteStringM, evalByteStringM, headBS,

	lenBodyToByteString, emptyBS, BS.concat,

	byteStringToInt, intToByteString,
	section, takeWords, takeLen, takeBS,

	takeLen',

	NamedCurve(..),
	ContentType(..),

	throwError,
	list,
	list1,
) where

import Prelude hiding (head, take, concat)
import qualified Prelude
import Numeric

import Control.Applicative ((<$>))
import Control.Monad

import qualified Data.ByteString as BS

import Types
-- import ByteStringMonad
-- import ToByteString

instance Show Random where
	show (Random r) =
		"(Random " ++ concatMap (`showHex` "") (BS.unpack r) ++ ")"

instance Parsable Random where
	parse = parseRandom
	toByteString = randomToByteString
	listLength _ = Nothing

parseRandom :: ByteStringM Random
parseRandom = Random <$> takeBS 32

instance Parsable' Random where
	parse' rd = Random `liftM` rd 32
	toByteString' = randomToByteString

randomToByteString :: Random -> BS.ByteString
randomToByteString (Random r) = r

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
	toByteString' = cipherSuiteToByteString

instance Parsable CipherSuite where
	parse = parseCipherSuite
	toByteString = cipherSuiteToByteString
	listLength _ = Just 2

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

instance Parsable' Version where
	parse' rd = do
		[vmjr, vmnr] <- takeWords' rd 2
		return $ Version vmjr vmnr
	toByteString' = versionToByteString
