{-# LANGUAGE OverloadedStrings, PackageImports #-}

module TestClientEcdhe (client) where

import HandshakeBase
import Data.HandleLike
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import "crypto-random" Crypto.Random
import qualified Codec.Bytable as B
import qualified Data.ByteString as BS

cipherSuites :: [CipherSuite]
cipherSuites = [
	CipherSuite ECDHE_RSA AES_128_CBC_SHA,
	CipherSuite RSA AES_128_CBC_SHA
	]

client :: (ValidateHandle h, CPRG g) =>
	g -> h -> X509.CertificateStore -> HandleMonad h ()
client g h _crtS = (`run` g) $ do
	t <- execHandshakeM h $ do
		cr <- randomByteString 32
		writeHandshake $ ClientHello (3, 3) cr (SessionId "")
			cipherSuites [CompressionMethodNull] Nothing
		ServerHello _v sr _sid cs _cm _e <- readHandshake
		setCipherSuite cs
		debug cs
		X509.CertificateChain [ccc] <- readHandshake
		let X509.PubKeyRSA pk =
			X509.certPubKey . X509.signedObject $ X509.getSigned ccc
		debug pk
		ServerKeyExEcdhe cv pnt ha sa _sn <- readHandshake
		ServerHelloDone <- readHandshake
		debug cv
		debug pnt
		debug ha
		debug sa
		sv <- withRandom $ generateSecret cv
		let cpv = B.encode $ calculatePublic cv sv
		writeHandshake $ ClientKeyExchange cpv
		generateKeys Client (cr, sr) $ calculateShared cv sv pnt
		putChangeCipherSpec >> flushCipherSuite Server
		writeHandshake =<< finishedHash Client
		getChangeCipherSpec >> flushCipherSuite Client
		fh <- finishedHash Server
		rfh <- readHandshake
		debug $ fh == rfh
	hlPut t request
	hlGetContent t >>= hlDebug t 5
	hlClose t

request :: BS.ByteString
request = "GET / HTTP/1.1\r\n\r\n"
