{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts, PackageImports #-}

module TlsClient (
	run, openServer, ValidateHandle(..), CertSecretKey,
	CipherSuite(..), KeyExchange(..), BulkEncryption(..) ) where

import Control.Monad (unless, liftM)
import Data.List (find, intersect)
import Data.HandleLike (HandleLike)
import "crypto-random" Crypto.Random (CPRG)

import qualified "monads-tf" Control.Monad.Error as E
import qualified Data.ByteString as BS
import qualified Data.ASN1.Types as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import qualified Codec.Bytable as B
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.PubKey.DH as DH
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Crypto.Types.PubKey.ECC as ECC
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA

import HandshakeBase (
	TlsM, run, HandshakeM, execHandshakeM, CertSecretKey(..),
		withRandom, randomByteString,
	TlsHandle,
		readHandshake, getChangeCipherSpec,
		writeHandshake, putChangeCipherSpec,
	ValidateHandle(..), handshakeValidate,
	ServerKeyExEcdhe(..), ServerKeyExDhe(..), ServerHelloDone(..),
	ClientHello(..), ServerHello(..), SessionId(..),
		CipherSuite(..), KeyExchange(..), BulkEncryption(..),
		CompressionMethod(..), HashAlgorithm(..), SignatureAlgorithm(..),
		setCipherSuite,
	CertificateRequest(..), ClientCertificateType(..),
	ClientKeyExchange(..), Epms(..),
		generateKeys, encryptRsa, rsaPadding,
	DigitallySigned(..), handshakeHash, flushCipherSuite,
	Side(..), RW(..), finishedHash,
	DhParam(..), generateKs, blindSign )

openServer :: (ValidateHandle h, CPRG g) => h -> [CipherSuite] ->
	[(CertSecretKey, X509.CertificateChain)] -> X509.CertificateStore ->
	TlsM h g (TlsHandle h g)
openServer h cscl crts ca = execHandshakeM h $ do
	(cr, sr, cs@(CipherSuite ke _)) <- hello cscl
	setCipherSuite cs
	case ke of
		RSA -> rsaHandshake cr sr crts ca
		DHE_RSA -> dheHandshake dhType cr sr crts ca
		ECDHE_RSA -> dheHandshake curveType cr sr crts ca
		ECDHE_ECDSA -> dheHandshake curveType cr sr crts ca
		_ -> error "not implemented"

hello :: (HandleLike h, CPRG g) =>
	[CipherSuite] -> HandshakeM h g (BS.ByteString, BS.ByteString, CipherSuite)
hello cscl = do
	cr <- randomByteString 32
	writeHandshake $ ClientHello (3, 3) cr (SessionId "")
		cscl' [CompressionMethodNull] Nothing
	ServerHello _v sr _sid cs _cm _e <- readHandshake
	return (cr, sr, cs)
	where
	cscl' = if b `elem` cscl then cscl else cscl ++ [b]
	b = CipherSuite RSA AES_128_CBC_SHA

rsaHandshake :: (ValidateHandle h, CPRG g) =>
 	BS.ByteString -> BS.ByteString ->
	[(CertSecretKey, X509.CertificateChain)] -> X509.CertificateStore ->
	HandshakeM h g ()
rsaHandshake cr sr crts ca = do
	cc@(X509.CertificateChain (c : _)) <- readHandshake
	vr <- handshakeValidate ca cc
	unless (null vr) $ E.throwError "TlsClient.rsaHandshake: validate failure"
	let X509.PubKeyRSA pk =
		X509.certPubKey . X509.signedObject $ X509.getSigned c
	crt <- clientCertificate crts
	pms <- ("\x03\x03" `BS.append`) `liftM` randomByteString 46
	generateKeys Client (cr, sr) pms
	writeHandshake . Epms =<< encryptRsa pk pms
	finishHandshake crt

dheHandshake :: (ValidateHandle h, CPRG g, KeyEx ke) =>
	ke -> BS.ByteString -> BS.ByteString ->
	[(CertSecretKey, X509.CertificateChain)] -> X509.CertificateStore ->
	HandshakeM h g ()
dheHandshake t cr sr crts ca = do
	cc@(X509.CertificateChain (c : _)) <- readHandshake
	case X509.certPubKey . X509.signedObject $ X509.getSigned c of
		X509.PubKeyRSA pk -> succeedHandshake t pk cr sr cc crts ca
		X509.PubKeyECDSA cv pnt ->
			succeedHandshake t (ek cv pnt) cr sr cc crts ca
		_ -> E.throwError "TlsClient.dheHandshake: not implemented"
	where ek cv pnt = ECDSA.PublicKey (ECC.getCurveByName cv) (point pnt)

succeedHandshake ::
	(ValidateHandle h, CPRG g, Verify pk, KeyEx ke) =>
	ke -> pk -> BS.ByteString -> BS.ByteString -> X509.CertificateChain ->
	[(CertSecretKey, X509.CertificateChain)] -> X509.CertificateStore ->
	HandshakeM h g ()
succeedHandshake t pk cr sr cc crts ca = do
	vr <- handshakeValidate ca cc
	unless (null vr) $
		E.throwError "TlsClient.succeedHandshake: validate failure"
	(ps, pv, ha, _sa, sn) <- getKeyEx
	let _ = ps `asTypeOf` t
	unless (verify ha pk sn $ BS.concat [cr, sr, B.encode ps, B.encode pv]) $
		E.throwError "TlsClient.succeedHandshake: verify failure"
	crt <- clientCertificate crts
	sv <- withRandom $ generateSecret ps
	generateKeys Client (cr, sr) $ calculateShared ps sv pv
	writeHandshake . ClientKeyExchange . B.encode $ calculatePublic ps sv
	finishHandshake crt

clientCertificate :: (HandleLike h, CPRG g) =>
	[(CertSecretKey, X509.CertificateChain)] ->
	HandshakeM h g (Maybe (CertSecretKey, X509.CertificateChain))
clientCertificate crts = do
	shd <- readHandshake
	case shd of
		Left (CertificateRequest csa hsa dn) -> do
			ServerHelloDone <- readHandshake
			case find (certIsOk csa hsa dn) crts of
				Just (sk, rcc) -> do
					writeHandshake rcc
					return $ Just (sk, rcc)
				_ -> error "no certificate"
		Right ServerHelloDone -> return Nothing
		_ -> error "bad"

finishHandshake :: (HandleLike h, CPRG g) =>
	Maybe (CertSecretKey, X509.CertificateChain) -> HandshakeM h g ()
finishHandshake crt = do
	hs <- handshakeHash
	case crt of
		Just (RsaKey csk, rcc) -> do
			let rcpk = let X509.CertificateChain (rccc : _) = rcc in
				getPubKey csk . X509.certPubKey .
					X509.signedObject $ X509.getSigned rccc
			writeHandshake . DigitallySigned (clAlgorithm csk) $
				clSign csk rcpk hs
		Just (EcdsaKey csk, rcc) -> do
			let rcpk = let X509.CertificateChain (rccc : _) = rcc in
				getPubKey csk . X509.certPubKey .
					X509.signedObject $ X509.getSigned rccc
			writeHandshake . DigitallySigned (clAlgorithm csk) $
				clSign csk rcpk hs
		_ -> return ()
	putChangeCipherSpec >> flushCipherSuite Write
	writeHandshake =<< finishedHash Client
	getChangeCipherSpec >> flushCipherSuite Read
	fh <- finishedHash Server
	rfh <- readHandshake
	unless (fh == rfh) $ E.throwError "finished hash failure"

certIsOk :: [ClientCertificateType] -> [(HashAlgorithm, SignatureAlgorithm)] ->
	[X509.DistinguishedName] -> (CertSecretKey, X509.CertificateChain) -> Bool
certIsOk cct hsa dn (k, c) = checkKey cct hsa k && checkCert cct hsa dn c

checkKey :: [ClientCertificateType] -> [(HashAlgorithm, SignatureAlgorithm)] ->
	CertSecretKey -> Bool
checkKey cct hsa (RsaKey _) =
	CTRsaSign `elem` cct || Rsa `elem` map snd hsa
checkKey cct hsa (EcdsaKey _) =
	CTEcdsaSign `elem` cct || Ecdsa `elem` map snd hsa

checkCert :: [ClientCertificateType] -> [(HashAlgorithm, SignatureAlgorithm)] ->
	[X509.DistinguishedName] -> X509.CertificateChain -> Bool
checkCert cct hsa dn (X509.CertificateChain cs@(co : _)) =
	checkPubKey cct hsa (pk co) && checkIssuer dn (map issuer cs)
	where
	obj = X509.signedObject . X509.getSigned
	issuer = X509.certIssuerDN . obj
	pk = X509.certPubKey . obj
checkCert _ _ _ _ = error "empty certificate chain"

checkPubKey :: [ClientCertificateType] -> [(HashAlgorithm, SignatureAlgorithm)] ->
	X509.PubKey -> Bool
checkPubKey cct hsa (X509.PubKeyRSA _) =
	CTRsaSign `elem` cct || Rsa `elem` map snd hsa
checkPubKey cct hsa (X509.PubKeyECDSA _ _) =
	CTEcdsaSign `elem` cct || Ecdsa `elem` map snd hsa
checkPubKey _ _ _ = False

checkIssuer :: [X509.DistinguishedName] -> [X509.DistinguishedName] -> Bool
checkIssuer = ((not . null) .) . intersect

dhType :: DH.Params
dhType = undefined

curveType :: ECC.Curve
curveType = undefined

class (DhParam bs, B.Bytable bs, B.Bytable (Public bs)) => KeyEx bs where
	getKeyEx :: (HandleLike h, CPRG g) => HandshakeM h g
		(bs, Public bs, HashAlgorithm, SignatureAlgorithm, BS.ByteString)

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
