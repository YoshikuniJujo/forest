{-# LANGUAGE OverloadedStrings, TypeFamilies, PackageImports, FlexibleContexts #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module TestClient ( CertSecretKey,
	client, CipherSuite(..), KeyExchange(..), BulkEncryption(..),
	ValidateHandle(..) ) where

import TlsClient
import Control.Monad
import "crypto-random" Crypto.Random
-- import HandshakeBase
import Data.HandleLike

import qualified Data.ByteString as BS
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509

cipherSuites :: [CipherSuite]
cipherSuites = [
	CipherSuite ECDHE_ECDSA AES_128_CBC_SHA256,
	CipherSuite ECDHE_ECDSA AES_128_CBC_SHA,
	CipherSuite ECDHE_RSA AES_128_CBC_SHA256,
	CipherSuite ECDHE_RSA AES_128_CBC_SHA,
	CipherSuite DHE_RSA AES_128_CBC_SHA256,
	CipherSuite DHE_RSA AES_128_CBC_SHA,
	CipherSuite RSA AES_128_CBC_SHA256,
	CipherSuite RSA AES_128_CBC_SHA ]

client :: (ValidateHandle h, CPRG g) => g -> h ->
	[(CertSecretKey, X509.CertificateChain)] ->
	X509.CertificateStore ->
	HandleMonad h ()
client g h crt crtS = (`run` g) $ do
	t <- openServer h cipherSuites crt crtS
	hlPut t request
	const () `liftM` hlGetContent t -- >>= hlDebug t 5

request :: BS.ByteString
request = "GET / HTTP/1.1\r\n\r\n"
