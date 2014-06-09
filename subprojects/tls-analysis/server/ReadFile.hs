{-# LANGUAGE OverloadedStrings, TypeFamilies, PackageImports #-}

module ReadFile (
	readRsaKey, readEcPrivKey, readCertificateChain, readCertificateStore,
) where

import Control.Applicative

import Data.X509
import Data.X509.File
import Data.X509.CertificateStore

import qualified Crypto.PubKey.RSA as RSA

import Data.Maybe
import Data.Bits
import Data.Word
import Data.PEM
import qualified Data.ByteString as BS

import Crypto.Types.PubKey.ECDSA
import Crypto.Types.PubKey.ECC

readCertificateChain :: FilePath -> IO CertificateChain
readCertificateChain = (CertificateChain <$>) . readSignedObject

readRsaKey :: FilePath -> IO RSA.PrivateKey
readRsaKey fp = do [PrivKeyRSA sk] <- readKeyFile fp; return sk

readCertificateStore :: [FilePath] -> IO CertificateStore
readCertificateStore fps =
	makeCertificateStore . concat <$> mapM readSignedObject fps

readEcPrivKey :: FilePath -> IO PrivateKey
readEcPrivKey fp = do
	Right [pem] <- pemParseBS <$> BS.readFile fp
	let	c = pemContent pem
		_ws = BS.unpack c
		body = BS.drop 6 c
		(pklen, body') = fromJust $ BS.uncons body
		pk = BS.take (fromIntegral pklen) body'
		_pkws = BS.unpack pk
	return . PrivateKey secp256r1 $ byteStringToInteger pk

secp256r1 :: Curve
secp256r1 = CurveFP $ CurvePrime p (CurveCommon a b g n h)
	where
	p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
	a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
	b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
	g = Point gx gy
	gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
	gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
	n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
	h = 0x01

byteStringToInteger :: BS.ByteString -> Integer
byteStringToInteger = wordsToIntegerBE . BS.unpack

wordsToIntegerBE :: [Word8] -> Integer
wordsToIntegerBE = wordsToIntegerLE . reverse

wordsToIntegerLE :: [Word8] -> Integer
wordsToIntegerLE [] = 0
wordsToIntegerLE (w : ws) = fromIntegral w .|. (wordsToIntegerLE ws `shiftL` 8)
