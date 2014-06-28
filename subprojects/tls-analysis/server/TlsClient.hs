{-# LANGUAGE OverloadedStrings, TypeFamilies, PackageImports, FlexibleContexts #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module TlsClient (
	run, openServer, ValidateHandle(..), ClSecretKey(..),
	CipherSuite(..), KeyExchange(..), BulkEncryption(..) ) where

-- import ClSecretKey
import Control.Monad
import qualified "monads-tf" Control.Monad.Error as E
import "crypto-random" Crypto.Random
import HandshakeBase
import Data.HandleLike

import qualified Data.ByteString as BS
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509

import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Crypto.PubKey.RSA as RSA

import qualified Data.ASN1.Types as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Codec.Bytable as B
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA256 as SHA256

import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.Types.PubKey.ECC as ECC
import qualified Crypto.PubKey.DH as DH

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

openServer :: (ValidateHandle h, CPRG g, ClSecretKey sk) =>
	h -> (sk, X509.CertificateChain) -> X509.CertificateStore ->
	TlsM h g (TlsHandle h g)
openServer h crt crtS = execHandshakeM h $ do
	(cr, sr, cs@(CipherSuite ke _)) <- hello
	setCipherSuite cs
	case ke of
		RSA -> rsaHandshake cr sr crt crtS
		DHE_RSA -> dheHandshake dhType cr sr crt crtS
		ECDHE_RSA -> dheHandshake curveType cr sr crt crtS
		ECDHE_ECDSA -> dheHandshake curveType cr sr crt crtS
		_ -> error "not implemented"

hello :: (HandleLike h, CPRG g) =>
	HandshakeM h g (BS.ByteString, BS.ByteString, CipherSuite)
hello = do
	cr <- randomByteString 32
	writeHandshake $ ClientHello (3, 3) cr (SessionId "")
		cipherSuites [CompressionMethodNull] Nothing
	ServerHello _v sr _sid cs _cm _e <- readHandshake
	return (cr, sr, cs)

rsaHandshake :: (ValidateHandle h, CPRG g, ClSecretKey sk) =>
 	BS.ByteString -> BS.ByteString ->
	(sk, X509.CertificateChain) ->
	X509.CertificateStore ->
	HandshakeM h g ()
rsaHandshake cr sr (csk, rcc) crtS = do
	cc@(X509.CertificateChain (ccc : _)) <- readHandshake
	vr <- handshakeValidate crtS cc
	unless (null vr) $ E.throwError "validate failure"
	let X509.PubKeyRSA pk =
		X509.certPubKey . X509.signedObject $ X509.getSigned ccc
	cReq <- clientCertificate rcc
	pms <- ("\x03\x03" `BS.append`) `liftM` randomByteString 46
	generateKeys Client (cr, sr) pms
	writeHandshake . Epms =<< encryptRsa pk pms
	finishHandshake cReq csk rcc

dheHandshake :: (ValidateHandle h, CPRG g, ClSecretKey sk, KeyEx ke) =>
	ke -> BS.ByteString -> BS.ByteString ->
	(sk, X509.CertificateChain) -> X509.CertificateStore ->
	HandshakeM h g ()
dheHandshake t cr sr (csk, rcc) crtS = do
	cc@(X509.CertificateChain (ccc : _)) <- readHandshake
	case X509.certPubKey . X509.signedObject $ X509.getSigned ccc of
		X509.PubKeyRSA pk -> succeedHandshake t pk cc cr sr csk rcc crtS
		X509.PubKeyECDSA _cv pnt -> succeedHandshake t
			(ECDSA.PublicKey secp256r1 $ point pnt)
			cc cr sr csk rcc crtS
		_ -> error "not implemented"

succeedHandshake ::
	(ValidateHandle h, CPRG g, ClSecretKey sk, Verify pk, KeyEx bs) =>
	bs -> pk -> X509.CertificateChain -> BS.ByteString -> BS.ByteString ->
	sk -> X509.CertificateChain -> X509.CertificateStore -> HandshakeM h g ()
succeedHandshake t pk cc cr sr csk rcc crtS = do
	vr <- handshakeValidate crtS cc
	unless (null vr) $ E.throwError "validate failure"
	(cv, pnt, ha, _sa, sn) <- getKeyEx
	let _ = cv `asTypeOf` t
	unless (verify ha pk sn $ BS.concat [cr, sr, B.encode cv, B.encode pnt]) $
		E.throwError "verify failure"
	cReq <- clientCertificate rcc
	sv <- withRandom $ generateSecret cv
	generateKeys Client (cr, sr) $ calculateShared cv sv pnt
	writeHandshake . ClientKeyExchange . B.encode $ calculatePublic cv sv
	finishHandshake cReq csk rcc

clientCertificate :: (HandleLike h, CPRG g) => X509.CertificateChain ->
	HandshakeM h g (Maybe (
		[ClientCertificateType],
		[(HashAlgorithm, SignatureAlgorithm)],
		[X509.DistinguishedName]))
clientCertificate rcc = do
	shd <- readHandshake
	cReq <- case shd of
		Left (CertificateRequest csa hsa dn) -> do
			ServerHelloDone <- readHandshake
			return $ Just (csa, hsa, dn)
		Right ServerHelloDone -> return Nothing
		_ -> error "bad"
	case cReq of
		Just _ -> writeHandshake rcc
		_ -> return ()
	return cReq

finishHandshake :: (HandleLike h, CPRG g, ClSecretKey sk) =>
	Maybe t -> sk -> X509.CertificateChain -> HandshakeM h g ()
finishHandshake cReq csk rcc = do
	let rcpk = let X509.CertificateChain (rccc : _) = rcc in getPubKey csk .
		X509.certPubKey . X509.signedObject $ X509.getSigned rccc
	hs <- handshakeHash
	case cReq of
		Just _ -> writeHandshake . DigitallySigned (clAlgorithm csk) $
			clSign csk rcpk hs
		_ -> return ()
	putChangeCipherSpec >> flushCipherSuite Write
	writeHandshake =<< finishedHash Client
	getChangeCipherSpec >> flushCipherSuite Read
	fh <- finishedHash Server
	rfh <- readHandshake
	unless (fh == rfh) $ E.throwError "finished hash failure"

dhType :: DH.Params
dhType = undefined

curveType :: ECC.Curve
curveType = undefined

class (DhParam bs, B.Bytable bs, B.Bytable (Public bs)) => KeyEx bs where
	getKeyEx :: (HandleLike h, CPRG g) => HandshakeM h g (bs, Public bs,
		HashAlgorithm, SignatureAlgorithm, BS.ByteString)

instance KeyEx ECC.Curve where
	getKeyEx = do
		ServerKeyExEcdhe cv pnt ha sa sn <- readHandshake
		return (cv, pnt, ha, sa, sn)

instance KeyEx DH.Params where
	getKeyEx = do
		ServerKeyExDhe ps pv ha sa sn <- readHandshake
		return (ps, pv, ha, sa, sn)

instance Verify RSA.PublicKey where
	verify = rsaVerify

rsaVerify :: HashAlgorithm -> RSA.PublicKey -> BS.ByteString -> BS.ByteString -> Bool
rsaVerify ha pk sn m = let
	(hs, oid0) = case ha of
		Sha1 -> (SHA1.hash, ASN1.OID [1, 3, 14, 3, 2, 26])
		Sha256 -> (SHA256.hash, ASN1.OID [2, 16, 840, 1, 101, 3, 4, 2, 1])
		_ -> error "not implemented"
	v = RSA.ep pk sn
	up = BS.tail . BS.dropWhile (== 255) $ BS.drop 2 v
	Right [ASN1.Start ASN1.Sequence,
		ASN1.Start ASN1.Sequence, oid, ASN1.Null, ASN1.End ASN1.Sequence,
		ASN1.OctetString o, ASN1.End ASN1.Sequence ] =
		ASN1.decodeASN1' ASN1.DER up in
	oid == oid0 && o == hs m

class Verify pk where
	verify :: HashAlgorithm ->
		pk -> BS.ByteString -> BS.ByteString -> Bool

instance Verify ECDSA.PublicKey where
	verify ha pk = let
		hs = case ha of
			Sha1 -> SHA1.hash
			Sha256 -> SHA256.hash
			_ -> error "not implemented" in
		ECDSA.verify hs pk . either error id . B.decode

point :: BS.ByteString -> ECC.Point
point s = let (x, y) = BS.splitAt 32 $ BS.drop 1 s in ECC.Point
	(either error id $ B.decode x)
	(either error id $ B.decode y)

class ClSecretKey sk where
	type SecPubKey sk
	getPubKey :: sk -> X509.PubKey -> SecPubKey sk
	clSign :: sk -> SecPubKey sk -> BS.ByteString -> BS.ByteString
	clAlgorithm :: sk -> (HashAlgorithm, SignatureAlgorithm)

instance ClSecretKey ECDSA.PrivateKey where
	type SecPubKey ECDSA.PrivateKey = ()
	getPubKey _ _ = ()
	clSign sk _ m = encodeSignature $ -- fromJust . ECDSA.signWith 4649 sk id
		blindSign 1 id sk (generateKs (SHA256.hash, 64) q x m) m
		where
		q = ECC.ecc_n . ECC.common_curve $ ECDSA.private_curve sk
		x = ECDSA.private_d sk
	clAlgorithm _ = (Sha256, Ecdsa)

encodeSignature :: ECDSA.Signature -> BS.ByteString
encodeSignature (ECDSA.Signature r s) = ASN1.encodeASN1' ASN1.DER [
	ASN1.Start ASN1.Sequence,
		ASN1.IntVal r, ASN1.IntVal s, ASN1.End ASN1.Sequence]

instance ClSecretKey RSA.PrivateKey where
	type SecPubKey RSA.PrivateKey = RSA.PublicKey
	getPubKey _ (X509.PubKeyRSA pk) = pk
	getPubKey _ _ = error "bad"
	clSign sk pk m = let pd = rsaPadding pk m in RSA.dp Nothing sk pd
	clAlgorithm _ = (Sha256, Rsa)
