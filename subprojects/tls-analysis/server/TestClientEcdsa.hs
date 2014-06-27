{-# LANGUAGE OverloadedStrings, PackageImports #-}

module TestClientEcdsa (client) where

import Control.Monad
import HandshakeBase
import Data.HandleLike
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import "crypto-random" Crypto.Random
import qualified Codec.Bytable as B
import qualified Data.ByteString as BS

import qualified Crypto.Hash.SHA1 as SHA1
-- import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.Types.PubKey.ECC as ECC

import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Crypto.PubKey.RSA as RSA

cipherSuites :: [CipherSuite]
cipherSuites = [
	CipherSuite ECDHE_ECDSA AES_128_CBC_SHA,
	CipherSuite ECDHE_RSA AES_128_CBC_SHA,
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

ecdsaHandshake :: (ValidateHandle h, CPRG g) => BS.ByteString -> BS.ByteString ->
	(RSA.PrivateKey, X509.CertificateChain) -> X509.CertificateStore ->
	HandshakeM h g ()
ecdsaHandshake cr sr (rsk, rcc) crtS = do
	let X509.PubKeyRSA rcpk = let X509.CertificateChain [rccc] = rcc in
		X509.certPubKey . X509.signedObject $ X509.getSigned rccc
	cc@(X509.CertificateChain [ccc]) <- readHandshake
	handshakeValidate crtS cc >>= debug
	let X509.PubKeyECDSA _scv spnt =
		X509.certPubKey . X509.signedObject $ X509.getSigned ccc
	ServerKeyExEcdhe cv pnt ha sa sn <- readHandshake
	let Right s = B.decode sn
	debug ("here" :: String)
	debug $ ECDSA.verify SHA1.hash
		(ECDSA.PublicKey secp256r1 $ point spnt) s $
		BS.concat [cr, sr, B.encode cv, B.encode pnt]
	shd <- readHandshake
	cReq <- case shd of
		Left (CertificateRequest csa hsa dn) -> do
			ServerHelloDone <- readHandshake
			return $ Just (csa, hsa, dn)
		Right ServerHelloDone -> return Nothing
		_ -> error "bad"
	debug ha
	debug sa
	sv <- withRandom $ generateSecret cv
	let cpv = B.encode $ calculatePublic cv sv
	case cReq of
		Just _ -> writeHandshake rcc
		_ -> return ()
	writeHandshake $ ClientKeyExchange cpv
	hs <- rsaPadding rcpk `liftM` handshakeHash
	case cReq of
		Just _ -> writeHandshake $ DigitallySigned (Sha256, Rsa) $
			RSA.dp Nothing rsk hs
		_ -> return ()
	generateKeys Client (cr, sr) $ calculateShared cv sv pnt
	putChangeCipherSpec >> flushCipherSuite Server
	writeHandshake =<< finishedHash Client
	getChangeCipherSpec >> flushCipherSuite Client
	fh <- finishedHash Server
	rfh <- readHandshake
	debug $ fh == rfh

client :: (ValidateHandle h, CPRG g) => g -> h ->
	(RSA.PrivateKey, X509.CertificateChain) -> X509.CertificateStore ->
	HandleMonad h ()
client g h rsa crtS = (`run` g) $ do
	t <- execHandshakeM h $ do
		(cr, sr, cs) <- hello
		setCipherSuite cs
		ecdsaHandshake cr sr rsa crtS
	hlPut t request
	hlGetContent t >>= hlDebug t 5
	hlClose t

request :: BS.ByteString
request = "GET / HTTP/1.1\r\n\r\n"

point :: BS.ByteString -> ECC.Point
point s = let (x, y) = BS.splitAt 32 $ BS.drop 1 s in ECC.Point
	(either error id $ B.decode x)
	(either error id $ B.decode y)
