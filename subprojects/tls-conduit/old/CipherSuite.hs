{-# LANGUAGE OverloadedStrings #-}

module CipherSuite (
	CipherSuites,
	cipherSuites,
	cipherSuitesToByteString,
	CipherSuite,
	parseCipherSuite) where

import Prelude hiding (take)

import Data.Conduit
import Data.Conduit.Binary

import Data.Word
import Data.ByteString.Lazy (toStrict)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

import Tools

cipherSuites :: Monad m => Consumer BS.ByteString m CipherSuites
cipherSuites = do
	len <- getLen 2
	css <- take len
	return $ readCipherSuites $ toStrict css

type CipherSuites = [CipherSuite]

readCipherSuites :: BS.ByteString -> CipherSuites
readCipherSuites "" = []
readCipherSuites src = let
	cs1 = BS.head src
	cs2 = BS.head $ BS.tail src in
	cipherSuite cs1 cs2 : readCipherSuites (BS.drop 2 src)

parseCipherSuite :: Monad m => Consumer BS.ByteString m CipherSuite
parseCipherSuite = do
	cs <- take 2
	let	cs1 = LBS.head cs
		cs2 = LBS.head $ LBS.tail cs
	return $ cipherSuite cs1 cs2

data CipherSuite
	= TLS_NULL_WITH_NULL_NULL
	| TLS_RSA_WITH_NULL_MD5
	| TLS_RSA_WITH_RC4_128_MD5
	| TLS_RSA_WITH_RC4_128_SHA
	| TLS_RSA_WITH_3DES_EDE_CBC_SHA
	| TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
	| TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
	| TLS_RSA_WITH_AES_128_CBC_SHA		-- mandatory
	| TLS_RSA_WITH_AES_256_CBC_SHA
	| TLS_DHE_DSS_WITH_AES_256_CBC_SHA
	| TLS_DHE_DSS_WITH_AES_128_CBC_SHA
	| TLS_DHE_RSA_WITH_AES_128_CBC_SHA
	| TLS_DHE_RSA_WITH_AES_256_CBC_SHA
	| TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
	| TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
	| TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
	| TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
	| TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
	| TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
	| TLS_RSA_WITH_SEED_CBC_SHA
	| TLS_EMPTY_RENEGOTIATION_INFO_SCSV
	| TLS_ECDH_ECDSA_WITH_RC4_128_SHA
	| TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
	| TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
	| TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
	| TLS_ECDH_ECDSA_WITH_NULL_SHA
	| TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
	| TLS_ECDH_RSA_WITH_RC4_128_SHA
	| TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
	| TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
	| TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
	| TLS_ECDHE_RSA_WITH_RC4_128_SHA
	| TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
	| TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
	| TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
	| TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
	| TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	| TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
	| SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA
	| CipherSuiteOthers Word8 Word8
	deriving (Show, Eq)

cipherSuite :: Word8 -> Word8 -> CipherSuite
cipherSuite 0x00 0x00 = TLS_NULL_WITH_NULL_NULL
cipherSuite 0x00 0x01 = TLS_RSA_WITH_NULL_MD5
cipherSuite 0x00 0x04 = TLS_RSA_WITH_RC4_128_MD5
cipherSuite 0x00 0x05 = TLS_RSA_WITH_RC4_128_SHA
cipherSuite 0x00 0x0a = TLS_RSA_WITH_3DES_EDE_CBC_SHA
cipherSuite 0x00 0x13 = TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
cipherSuite 0x00 0x16 = TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
cipherSuite 0x00 0x2f = TLS_RSA_WITH_AES_128_CBC_SHA
cipherSuite 0x00 0x32 = TLS_DHE_DSS_WITH_AES_128_CBC_SHA
cipherSuite 0x00 0x33 = TLS_DHE_RSA_WITH_AES_128_CBC_SHA
cipherSuite 0x00 0x35 = TLS_RSA_WITH_AES_256_CBC_SHA
cipherSuite 0x00 0x38 = TLS_DHE_DSS_WITH_AES_256_CBC_SHA
cipherSuite 0x00 0x39 = TLS_DHE_RSA_WITH_AES_256_CBC_SHA
cipherSuite 0x00 0x41 = TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
cipherSuite 0x00 0x44 = TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
cipherSuite 0x00 0x45 = TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
cipherSuite 0x00 0x84 = TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
cipherSuite 0x00 0x87 = TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
cipherSuite 0x00 0x88 = TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
cipherSuite 0x00 0x96 = TLS_RSA_WITH_SEED_CBC_SHA
cipherSuite 0x00 0xff = TLS_EMPTY_RENEGOTIATION_INFO_SCSV
cipherSuite 0xc0 0x02 = TLS_ECDH_ECDSA_WITH_RC4_128_SHA
cipherSuite 0xc0 0x03 = TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
cipherSuite 0xc0 0x04 = TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
cipherSuite 0xc0 0x05 = TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
cipherSuite 0xc0 0x07 = TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
cipherSuite 0xc0 0x08 = TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
cipherSuite 0xc0 0x09 = TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
cipherSuite 0xc0 0x0a = TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
cipherSuite 0xc0 0x0c = TLS_ECDH_RSA_WITH_RC4_128_SHA
cipherSuite 0xc0 0x0d = TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
cipherSuite 0xc0 0x0e = TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
cipherSuite 0xc0 0x0f = TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
cipherSuite 0xc0 0x11 = TLS_ECDHE_RSA_WITH_RC4_128_SHA
cipherSuite 0xc0 0x12 = TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
cipherSuite 0xc0 0x13 = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
cipherSuite 0xc0 0x14 = TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
cipherSuite 0xfe 0xff = SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA
cipherSuite w1 w2 = CipherSuiteOthers w1 w2

cipherSuitesToByteString :: CipherSuites -> BS.ByteString
cipherSuitesToByteString css =
	lenToBS 2 (2 * length css)
		`BS.append` BS.concat (map cipherSuiteToByteString css)

cipherSuiteToByteString :: CipherSuite -> BS.ByteString
cipherSuiteToByteString TLS_NULL_WITH_NULL_NULL = "\x00\x00"
cipherSuiteToByteString TLS_RSA_WITH_NULL_MD5 = "\x00\x01"
cipherSuiteToByteString TLS_RSA_WITH_RC4_128_MD5 = "\x00\x04"
cipherSuiteToByteString TLS_RSA_WITH_RC4_128_SHA = "\x00\x05"
cipherSuiteToByteString TLS_RSA_WITH_3DES_EDE_CBC_SHA = "\x00\x0a"
cipherSuiteToByteString TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = "\x00\x13"
cipherSuiteToByteString TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = "\x00\x16"
cipherSuiteToByteString TLS_RSA_WITH_AES_128_CBC_SHA = "\x00\x2f"
cipherSuiteToByteString TLS_DHE_DSS_WITH_AES_128_CBC_SHA = "\x00\x32"
cipherSuiteToByteString TLS_DHE_RSA_WITH_AES_128_CBC_SHA = "\x00\x33"
cipherSuiteToByteString TLS_RSA_WITH_AES_256_CBC_SHA = "\x00\x35"
cipherSuiteToByteString TLS_DHE_DSS_WITH_AES_256_CBC_SHA = "\x00\x38"
cipherSuiteToByteString TLS_DHE_RSA_WITH_AES_256_CBC_SHA = "\x00\x39"
cipherSuiteToByteString TLS_RSA_WITH_CAMELLIA_128_CBC_SHA = "\x00\x41"
cipherSuiteToByteString TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA = "\x00\x44"
cipherSuiteToByteString TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = "\x00\x45"
cipherSuiteToByteString TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = "\x00\x84"
cipherSuiteToByteString TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = "\x00\x87"
cipherSuiteToByteString TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = "\x00\x88"
cipherSuiteToByteString TLS_RSA_WITH_SEED_CBC_SHA = "\x00\x96"
cipherSuiteToByteString TLS_EMPTY_RENEGOTIATION_INFO_SCSV = "\x00\xff"
cipherSuiteToByteString TLS_ECDH_ECDSA_WITH_RC4_128_SHA = "\xc0\x02"
cipherSuiteToByteString TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = "\xc0\x03"
cipherSuiteToByteString TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = "\xc0\x04"
cipherSuiteToByteString TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = "\xc0\x05"
cipherSuiteToByteString TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = "\xc0\x07"
cipherSuiteToByteString TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = "\xc0\x08"
cipherSuiteToByteString TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = "\xc0\x09"
cipherSuiteToByteString TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = "\xc0\x0a"
cipherSuiteToByteString TLS_ECDH_RSA_WITH_RC4_128_SHA = "\xc0\x0c"
cipherSuiteToByteString TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = "\xc0\x0d"
cipherSuiteToByteString TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = "\xc0\x0e"
cipherSuiteToByteString TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = "\xc0\x0f"
cipherSuiteToByteString TLS_ECDHE_RSA_WITH_RC4_128_SHA = "\xc0\x11"
cipherSuiteToByteString TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = "\xc0\x12"
cipherSuiteToByteString TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = "\xc0\x13"
cipherSuiteToByteString TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = "\xc0\x14"
cipherSuiteToByteString SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA = "\xfe\xff"
cipherSuiteToByteString _ = error "not implemented"
