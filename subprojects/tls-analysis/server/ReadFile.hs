{-# LANGUAGE OverloadedStrings, TypeFamilies #-}

module ReadFile (
	readRsaKey, readEcdsaKey, readCertificateChain, readCertificateStore
) where

import Control.Applicative ((<$>))
import Control.Arrow
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

readEcdsaKey :: FilePath -> IO ECDSA.PrivateKey
readEcdsaKey = (either error id . parseEcdsaKey <$>) . BS.readFile

readCertificateChain :: FilePath -> IO X509.CertificateChain
readCertificateChain = (X509.CertificateChain <$>) . X509.readSignedObject

readCertificateStore :: [FilePath] -> IO X509.CertificateStore
readCertificateStore fps =
	X509.makeCertificateStore . concat <$> mapM X509.readSignedObject fps

parseEcdsaKey :: BS.ByteString -> Either String ECDSA.PrivateKey
parseEcdsaKey bs = do
	pems <- either (Left . show) Right $ PEM.pemParseBS bs
	pem <- fromSingle (msgp ++ "not single pem") pems
	pemc <- case pem of
		PEM.PEM {
			PEM.pemName = "EC PRIVATE KEY",
			PEM.pemHeader = [],
			PEM.pemContent = c } -> Right c
		_ -> Left $ msgp ++ "bad PEM structure"
	asn <- either (Left . show) Right $ ASN1.decodeASN1' ASN1.DER pemc
	(sk, oid, pk) <- case asn of
		[ASN1.Start ASN1.Sequence,
			ASN1.IntVal 1,
			ASN1.OctetString s,
			ASN1.Start (ASN1.Container ASN1.Context 0),
				o, ASN1.End (ASN1.Container ASN1.Context 0),
			ASN1.Start (ASN1.Container ASN1.Context 1),
				ASN1.BitString (ASN1.BitArray _pbkl p),
				ASN1.End (ASN1.Container ASN1.Context 1),
			ASN1.End ASN1.Sequence] -> Right (s, o, p)
		_ -> Left $ msgp ++ "bad ASN.1 structure"
	unless (oid == prime256v1) . Left $ msgp ++ "not implemented curve"
	tpk <- case BS.uncons pk of
		Just (4, t) -> Right t
		_ -> Left $ msgp ++ "not implemented point format"
	let	(mx, my) = B.fromByteString *** B.fromByteString $ BS.splitAt 32 tpk
	x <- mx
	y <- my
	s <- B.fromByteString sk
	unless (ECC.Point x y == ECC.pointMul secp256r1 s g) .
		Left $ msgp ++ "bad public key"
	return $ ECDSA.PrivateKey secp256r1 s
	where
	msgp = "ReadFile.parseEcdsaKey: "
	secp256r1 = ECC.CurveFP $ ECC.CurvePrime pr (ECC.CurveCommon a b g n h)
	pr = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
	a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
	b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
	g = ECC.Point gx gy
	gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
	gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
	n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
	h = 0x01
	prime256v1 = ASN1.OID [1, 2, 840, 10045, 3, 1, 7]
	fromSingle _ [x] = Right x
	fromSingle msg _ = Left msg
