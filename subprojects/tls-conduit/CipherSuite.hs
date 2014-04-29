{-# LANGUAGE OverloadedStrings #-}

module CipherSuite (CipherSuites, cipherSuites) where

import Prelude hiding (take)

import Data.Conduit
import Data.Conduit.Binary

import Data.Word
import qualified Data.ByteString as BS
import Data.ByteString.Lazy (toStrict)

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

data CipherSuite
	= TLS_NULL_WITH_NULL_NULL
	| TLS_RSA_WITH_NULL_MD5
	| TLS_RSA_WITH_AES_128_CBC_SHA		-- mandatory
	| TLS_EMPTY_RENEGOTIATION_INFO_SCSV
	| TLS_ECDH_ECDSA_WITH_NULL_SHA
	| TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
	| TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
	| TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	| CipherSuiteOthers Word8 Word8
	deriving (Show, Eq)

cipherSuite :: Word8 -> Word8 -> CipherSuite
cipherSuite 0x00 0x00 = TLS_NULL_WITH_NULL_NULL
cipherSuite 0x00 0x01 = TLS_NULL_WITH_NULL_NULL
cipherSuite 0x00 0xff = TLS_EMPTY_RENEGOTIATION_INFO_SCSV
cipherSuite 0x00 0x2f = TLS_RSA_WITH_AES_128_CBC_SHA
cipherSuite 0xc0 0x09 = TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
cipherSuite 0xc0 0x0a = TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
cipherSuite 0xc0 0x13 = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
cipherSuite w1 w2 = CipherSuiteOthers w1 w2
