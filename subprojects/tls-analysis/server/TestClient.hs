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

import qualified Data.ASN1.Types as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Codec.Bytable as B
import qualified Crypto.Hash.SHA1 as SHA1

cipherSuites :: [CipherSuite]
cipherSuites = [
	CipherSuite DHE_RSA AES_128_CBC_SHA,
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
			DHE_RSA -> dheHandshake cr sr rsa crtS
			_ -> error "not implemented"
	hlPut t request
	hlGetContent t >>= hlDebug t 5
	return ()

request :: BS.ByteString
request = "GET / HTTP/1.1\r\n\r\n"

dheHandshake :: (ValidateHandle h, CPRG g) =>
	BS.ByteString -> BS.ByteString ->
	(RSA.PrivateKey, X509.CertificateChain) -> X509.CertificateStore ->
	HandshakeM h g ()
dheHandshake cr sr (rsk, rcc) _crtS = do
	let X509.PubKeyRSA rcpk = let X509.CertificateChain [rccc] = rcc in
		X509.certPubKey . X509.signedObject $ X509.getSigned rccc
	X509.CertificateChain [ccc] <- readHandshake
	let X509.PubKeyRSA pk =
		X509.certPubKey . X509.signedObject $ X509.getSigned ccc
	ServerKeyExDhe edp pv ha sa sn <- readHandshake
	let	v = RSA.ep pk sn
		v' = BS.tail . BS.dropWhile (== 255) $ BS.drop 2 v
		Right [ASN1.Start ASN1.Sequence, ASN1.Start ASN1.Sequence,
			ASN1.OID [1, 3, 14, 3, 2, 26], ASN1.Null,
			ASN1.End ASN1.Sequence,
			ASN1.OctetString v'', ASN1.End ASN1.Sequence
			] = ASN1.decodeASN1' ASN1.DER v'
	debug v''
	debug . SHA1.hash $ BS.concat [cr, sr, B.encode edp, B.encode pv]
	shd <- readHandshake
	cReq <- case shd of
		Left (CertificateRequest csa hsa dn) -> do
			ServerHelloDone <- readHandshake
			return $ Just (csa, hsa, dn)
		Right ServerHelloDone -> return Nothing
		_ -> error "bad"
	debug ha
	debug sa
	sv <- withRandom $ generateSecret edp
	let cpv = B.encode $ calculatePublic edp sv
	case cReq of
		Just _ -> writeHandshake rcc
		_ -> return ()
	writeHandshake $ ClientKeyExchange cpv
	hs <- rsaPadding rcpk `liftM` handshakeHash
	case cReq of
		Just _ -> writeHandshake $ DigitallySigned (Sha256, Rsa) $
			RSA.dp Nothing rsk hs
		_ -> return ()
	generateKeys Client (cr, sr) $ calculateShared edp sv pv
	putChangeCipherSpec >> flushCipherSuite Server
	writeHandshake =<< finishedHash Client
	getChangeCipherSpec >> flushCipherSuite Client
	fh <- finishedHash Server
	rfh <- readHandshake
	debug $ fh == rfh
