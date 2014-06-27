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

hello :: (HandleLike h, CPRG g) =>
	HandshakeM h g (BS.ByteString, BS.ByteString, CipherSuite)
hello = do
	cr <- randomByteString 32
	writeHandshake $ ClientHello (3, 3) cr (SessionId "")
		cipherSuites [CompressionMethodNull] Nothing
	ServerHello _v sr _sid cs _cm _e <- readHandshake
	return (cr, sr, cs)

rsaHandshake :: (ValidateHandle h, CPRG g) =>
 	BS.ByteString -> BS.ByteString ->
	(RSA.PrivateKey, X509.CertificateChain) ->
	X509.CertificateStore ->
	HandshakeM h g ()
rsaHandshake cr sr (rsk, rcc) crtS = do
	let X509.PubKeyRSA rcpk = let X509.CertificateChain [rccc] = rcc in
		X509.certPubKey . X509.signedObject $ X509.getSigned rccc
	cc@(X509.CertificateChain [ccc]) <- readHandshake
	shd <- readHandshake
	cReq <- case shd of
		Left (CertificateRequest sa hsa dn) -> do
			ServerHelloDone <- readHandshake
			return $ Just (sa, hsa, dn)
		Right ServerHelloDone -> return Nothing
		_ -> error "bad"
	handshakeValidate crtS cc >>= debug
	let X509.PubKeyRSA pk =
		X509.certPubKey . X509.signedObject $ X509.getSigned ccc
	pms <- ("\x03\x03" `BS.append`) `liftM` randomByteString 46
	epms <- encryptRsa pk pms
	case cReq of
		Just _ -> writeHandshake rcc
		_ -> return ()
	writeHandshake $ Epms epms
	generateKeys Client (cr, sr) pms
	hs <- rsaPadding rcpk `liftM` handshakeHash
	case cReq of
		Just _ -> writeHandshake $ DigitallySigned (Sha256, Rsa) $
			RSA.dp Nothing rsk hs
		_ -> return ()
	putChangeCipherSpec >> flushCipherSuite Server
	writeHandshake =<< finishedHash Client
	getChangeCipherSpec >> flushCipherSuite Client
	fh <- finishedHash Server
	rfh <- readHandshake
	debug $ fh == rfh

client :: (ValidateHandle h, CPRG g) => g -> h ->
	(RSA.PrivateKey, X509.CertificateChain) ->
	X509.CertificateStore ->
	HandleMonad h ()
client g h rsa crtS = (`run` g) $ do
	t <- execHandshakeM h $ do
		(cr, sr, cs@(CipherSuite ke _)) <- hello
		setCipherSuite cs
		case ke of
			RSA -> rsaHandshake cr sr rsa crtS
			_ -> error "not implemented"
	hlPut t request
	hlGetContent t >>= hlDebug t 5
	return ()

request :: BS.ByteString
request = "GET / HTTP/1.1\r\n\r\n"
