{-# LANGUAGE OverloadedStrings, PackageImports #-}

module TestClient (
	client
) where

-- import Control.Applicative
import Control.Monad
import "crypto-random" Crypto.Random
import HandshakeBase
import Data.HandleLike

import qualified Data.ByteString as BS
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509

cipherSuites :: [CipherSuite]
cipherSuites = [
--	CipherSuite DHE_RSA AES_128_CBC_SHA,
	CipherSuite RSA AES_128_CBC_SHA
 ]

client :: (ValidateHandle h, CPRG g) =>
	g -> h -> X509.CertificateStore -> HandleMonad h ()
client g h crtS = (`run` g) $ do
	t <- execHandshakeM h $ do
		cr <- randomByteString 32
		writeHandshake $ ClientHello (3, 3) cr (SessionId "")
			cipherSuites [CompressionMethodNull] Nothing
		ServerHello _v sr _sid cs _cm _e <- readHandshake
		cc@(X509.CertificateChain [ccc]) <- readHandshake
		ServerHelloDone <- readHandshake
		setCipherSuite cs
		handshakeValidate crtS cc >>= debug
		debug cs
		debug . X509.certSubjectDN . X509.signedObject $ X509.getSigned ccc
		let X509.PubKeyRSA pk =
			X509.certPubKey . X509.signedObject $ X509.getSigned ccc
		pms <- ("\x03\x03" `BS.append`) `liftM` randomByteString 46
		epms <- encryptRsa pk pms
		writeHandshake $ Epms epms
		generateKeys Client (cr, sr) pms
		putChangeCipherSpec >> flushCipherSuite Server
		writeHandshake =<< finishedHash Client
		getChangeCipherSpec >> flushCipherSuite Client
		fh <- finishedHash Server
		rfh <- readHandshake
		debug $ fh == rfh
		return ()
	hlPut t request
	hlGetContent t >>= hlDebug t 5
	return ()

request :: BS.ByteString
request = "GET / HTTP/1.1\r\n\r\n"
