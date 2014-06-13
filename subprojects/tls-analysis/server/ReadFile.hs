{-# LANGUAGE OverloadedStrings, TypeFamilies #-}

module ReadFile (
	readRsaKey, readEcdsaKey, readCertificateChain, readCertificateStore
) where

import Control.Applicative ((<$>))
import Control.Monad (unless)

import qualified Codec.Bytable as B
import qualified Data.ByteString as BS
import qualified Data.ASN1.Types as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Data.ASN1.BitArray as ASN1
import qualified Data.PEM as PEM
import qualified Data.X509 as X509
import qualified Data.X509.File as X509
import qualified Data.X509.CertificateStore as X509
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.Types.PubKey.ECC as ECC
import qualified Crypto.Types.PubKey.ECDSA as ECDSA

readRsaKey :: FilePath -> IO RSA.PrivateKey
readRsaKey fp = do
	ks <- X509.readKeyFile fp
	case ks of
		[X509.PrivKeyRSA sk] -> return sk
		_ -> error "ReadFile.readRsaKey: Not single RSA key"

fromRight :: Show a => String -> Either a b -> b
fromRight msg e = case e of
	Left err -> error $ msg ++ "ReadFile.fromRight" ++ show err
	Right x -> x

fromSingle :: String -> [a] -> a
fromSingle msg l = case l of
	[x] -> x
	_ -> error $ msg ++ "ReadFile.fromSingle"

readEcdsaKey :: FilePath -> IO ECDSA.PrivateKey
readEcdsaKey fp = do
	PEM.PEM {
		PEM.pemName = "EC PRIVATE KEY",
		PEM.pemHeader = [],
		PEM.pemContent = pem } <-
		fromSingle "ReadFile.readEcdsaKey: pem not single: "
			. fromRight "ReadFile.readEcdsaKey: pem parse error: "
			.  PEM.pemParseBS <$> BS.readFile fp
	case ASN1.decodeASN1' ASN1.DER pem of
		Right [	ASN1.Start ASN1.Sequence,
				ASN1.IntVal 1,
				ASN1.OctetString bssk,
				ASN1.Start (ASN1.Container ASN1.Context 0),
					oid,
				ASN1.End (ASN1.Container ASN1.Context 0),
				ASN1.Start (ASN1.Container ASN1.Context 1),
					ASN1.BitString (ASN1.BitArray _pbkl pbk),
				ASN1.End (ASN1.Container ASN1.Context 1),
			ASN1.End ASN1.Sequence] -> do
			unless (oid == prime256v1) $ error "not implemented curve"
			let	sk = let Right s = B.fromByteString bssk in s :: Integer
				Just (4, bsp) = BS.uncons pbk
				(bsx, bsy) = BS.splitAt 32 bsp
				Right x = B.fromByteString bsx :: Either String Integer
				Right y = B.fromByteString bsy :: Either String Integer
				pubkey = ECC.Point x y
				calcPubkey = ECC.pointMul secp256r1 sk g
			unless (pubkey == calcPubkey) $ error "bad public key"
			return $ ECDSA.PrivateKey secp256r1 sk
				
		Left msg -> error $ show msg
		_ -> error $ "ReadFile.readEcdsaKey:" ++
			"not implemented or bad data structure"
	where
	secp256r1 = ECC.CurveFP $ ECC.CurvePrime p (ECC.CurveCommon a b g n h)
	p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
	a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
	b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
	g = ECC.Point gx gy
	gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
	gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
	n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
	h = 0x01
	prime256v1 = ASN1.OID [1, 2, 840, 10045, 3, 1, 7]

readCertificateChain :: FilePath -> IO X509.CertificateChain
readCertificateChain = (X509.CertificateChain <$>) . X509.readSignedObject

readCertificateStore :: [FilePath] -> IO X509.CertificateStore
readCertificateStore fps =
	X509.makeCertificateStore . concat <$> mapM X509.readSignedObject fps
