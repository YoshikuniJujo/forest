{-# LANGUAGE OverloadedStrings, PackageImports #-}

module TestClient (
	client
) where

import "crypto-random" Crypto.Random
import HandshakeBase
import Data.HandleLike

import qualified Data.X509 as X509

cipherSuites :: [CipherSuite]
cipherSuites = [
--	CipherSuite DHE_RSA AES_128_CBC_SHA,
	CipherSuite RSA AES_128_CBC_SHA
 ]

client :: (HandleLike h, CPRG g) => g -> h -> HandleMonad h ()
client g h = (`run` g) $ do
	_t <- execHandshakeM h $ do
		cr <- randomByteString 32
		writeHandshake $ ClientHello (3, 3) cr (SessionId "")
			cipherSuites [CompressionMethodNull] Nothing
		ServerHello _v _sr _sid cs _cm _e <- readHandshake
		X509.CertificateChain [cc] <- readHandshake
		ServerHelloDone <- readHandshake
		debug cs
		debug . X509.certSubjectDN . X509.signedObject $ X509.getSigned cc
		return ()
	return ()
