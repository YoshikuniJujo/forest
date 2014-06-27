{-# LANGUAGE OverloadedStrings, PackageImports #-}

module TestClientEcdsa (client) where

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

cipherSuites :: [CipherSuite]
cipherSuites = [
	CipherSuite ECDHE_ECDSA AES_128_CBC_SHA,
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
		let X509.PubKeyECDSA scv spnt =
			X509.certPubKey . X509.signedObject $ X509.getSigned ccc
		debug scv
		debug spnt
		ServerKeyExEcdhe cv pnt ha sa sn <- readHandshake
		let Right s = B.decode sn
		debug ("here" :: String)
		debug $ ECDSA.verify SHA1.hash
			(ECDSA.PublicKey secp256r1 $ point spnt) s $
			BS.concat [cr, sr, B.encode cv, B.encode pnt]
		ServerHelloDone <- readHandshake
--		debug cv
--		debug pnt
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

point :: BS.ByteString -> ECC.Point
point s = let (x, y) = BS.splitAt 32 $ BS.drop 1 s in ECC.Point
	(either error id $ B.decode x)
	(either error id $ B.decode y)
