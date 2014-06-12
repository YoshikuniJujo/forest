{-# LANGUAGE OverloadedStrings #-}

module CipherSuite (
	CipherSuite(..), CipherSuiteKeyEx(..), CipherSuiteMsgEnc(..),
) where

import qualified Codec.Bytable as B
import Data.Word
import qualified Data.ByteString as BS

data CipherSuite
	= CipherSuite CipherSuiteKeyEx CipherSuiteMsgEnc
	| CipherSuiteRaw Word8 Word8
	deriving (Show, Read, Eq)

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


instance B.Bytable CipherSuite where
	fromByteString = byteStringToCipherSuite
	toByteString = cipherSuiteToByteString

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
