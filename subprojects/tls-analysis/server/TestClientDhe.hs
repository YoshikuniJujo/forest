{-# LANGUAGE OverloadedStrings, PackageImports #-}

module TestClientDhe (client) where

import HandshakeBase
import Data.HandleLike
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import "crypto-random" Crypto.Random
import qualified Codec.Bytable as B

import qualified Data.ByteString as BS

import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Crypto.Hash.SHA1 as SHA1

import qualified Data.ASN1.Types as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.BinaryEncoding as ASN1

cipherSuites :: [CipherSuite]
cipherSuites = [
	CipherSuite DHE_RSA AES_128_CBC_SHA,
	CipherSuite RSA AES_128_CBC_SHA ]

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
		ServerHelloDone <- readHandshake
--		debug edp
--		debug pv
		debug ha
		debug sa
		sv <- withRandom $ generateSecret edp
		let cpv = B.encode $ calculatePublic edp sv
		writeHandshake $ ClientKeyExchange cpv
		generateKeys Client (cr, sr) $ calculateShared edp sv pv
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
