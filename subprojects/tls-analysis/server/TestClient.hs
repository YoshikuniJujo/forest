{-# LANGUAGE OverloadedStrings, PackageImports #-}

module TestClient (client) where

-- import Control.Applicative
import Control.Monad
import "crypto-random" Crypto.Random
import HandshakeBase
import Data.HandleLike

import qualified Data.ByteString as BS
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509

import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA

cipherSuites :: [CipherSuite]
cipherSuites = [
--	CipherSuite DHE_RSA AES_128_CBC_SHA,
	CipherSuite RSA AES_128_CBC_SHA
 ]

client :: (ValidateHandle h, CPRG g) => g -> h ->
	(RSA.PrivateKey, X509.CertificateChain) ->
	X509.CertificateStore ->
	HandleMonad h ()
client g h (rsk, rcc) crtS = (`run` g) $ do
	let X509.PubKeyRSA rcpk = let X509.CertificateChain [rccc] = rcc in
		X509.certPubKey . X509.signedObject $ X509.getSigned rccc
	t <- execHandshakeM h $ do
		cr <- randomByteString 32
		writeHandshake $ ClientHello (3, 3) cr (SessionId "")
			cipherSuites [CompressionMethodNull] Nothing
		ServerHello _v sr _sid cs _cm _e <- readHandshake
		cc@(X509.CertificateChain [ccc]) <- readHandshake
		CertificateRequest _ _ _ <- readHandshake -- client certificate
		ServerHelloDone <- readHandshake
		setCipherSuite cs
		handshakeValidate crtS cc >>= debug
		debug cs
		debug . X509.certSubjectDN . X509.signedObject $ X509.getSigned ccc
		let X509.PubKeyRSA pk =
			X509.certPubKey . X509.signedObject $ X509.getSigned ccc
		pms <- ("\x03\x03" `BS.append`) `liftM` randomByteString 46
		epms <- encryptRsa pk pms
		writeHandshake rcc -- client certificate
		writeHandshake $ Epms epms
		generateKeys Client (cr, sr) pms
		hs <- rsaPadding rcpk `liftM` handshakeHash
		writeHandshake $ DigitallySigned (Sha256, Rsa) $ RSA.dp Nothing rsk hs -- client certificate
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