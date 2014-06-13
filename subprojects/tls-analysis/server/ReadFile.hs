{-# LANGUAGE OverloadedStrings, TypeFamilies #-}

module ReadFile (
	readRsaKey, readEcdsaKey, readCertificateChain, readCertificateStore
) where

import Control.Applicative ((<$>))
import Control.Monad (unless)
import Data.PEM (PEM(..), pemParseBS)
import Data.X509 (CertificateChain(..), PrivKey(..))
import Data.X509.File (readSignedObject, readKeyFile)
import Data.X509.CertificateStore (CertificateStore, makeCertificateStore)

import qualified Codec.Bytable as B
import qualified Data.ByteString as BS
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.Types.PubKey.ECC as ECC
import qualified Crypto.Types.PubKey.ECDSA as ECDSA

import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.BitArray

readRsaKey :: FilePath -> IO RSA.PrivateKey
readRsaKey fp = do
	ks <- readKeyFile fp
	case ks of
		[PrivKeyRSA sk] -> return sk
		_ -> error "Not single RSA key"

readEcdsaKey :: FilePath -> IO ECDSA.PrivateKey
readEcdsaKey fp = do
	Right [pem] <- pemParseBS <$> BS.readFile fp
	let	c = pemContent pem
		asn = decodeASN1' DER c
	case asn of
		Right [Start Sequence, IntVal 1, OctetString bssk,
			Start (Container Context 0), oid, End (Container Context 0),
			Start (Container Context 1), BitString (BitArray _pbkl pbk),
			End (Container Context 1), End Sequence] -> do
			let	sk = let Right s = B.fromByteString bssk in s :: Integer
			unless (oid == prime256v1) $ error "not implemented curve"
			putStrLn $ "Secret: " ++ show sk
--				(let Right s = B.fromByteString sk in s :: Integer)
			putStrLn $ "Public: " ++ show pbk
			putStrLn $ "length: " ++ show (BS.length pbk)
			let	Just (4, p) = BS.uncons pbk
				(bsx, bsy) = BS.splitAt 32 p
				Right x = B.fromByteString bsx :: Either String Integer
				Right y = B.fromByteString bsy :: Either String Integer
				pubkey = ECC.Point x y
				calcPubkey = ECC.pointMul secp256r1 sk g
			putStrLn $ "x = " ++ show x
			putStrLn $ "y = " ++ show y
			putStrLn $ "Public: " ++ show (ECC.pointMul secp256r1 sk g)
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
	g = ECC.Point x y
	x = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
	y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
	n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
	h = 0x01
	prime256v1 = OID [1, 2, 840, 10045, 3, 1, 7]

readCertificateChain :: FilePath -> IO CertificateChain
readCertificateChain = (CertificateChain <$>) . readSignedObject

readCertificateStore :: [FilePath] -> IO CertificateStore
readCertificateStore fps =
	makeCertificateStore . concat <$> mapM readSignedObject fps
