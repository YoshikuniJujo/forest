{-# LANGUAGE TypeFamilies, PackageImports #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module KeyAgreement (
	Base(..), NoDH(..), Curve(..), secp256r1, DH.Params(..), dhparams
) where

import "crypto-random" Crypto.Random (CPRG(..))
import qualified Data.ByteString as BS

import qualified Codec.Bytable as B

import qualified Crypto.PubKey.DH as DH
import qualified Crypto.Types.PubKey.DH as DH

import Data.Word
import Control.Applicative

import System.IO.Unsafe

import Crypto.Types.PubKey.ECC
import Crypto.PubKey.ECC.Prim

-- import qualified Crypto.Types.PubKey.ECC as ECC

class Base b where
	type Param b
	type Secret b
	type Public b
	generateBase :: CPRG g => g -> Param b -> (b, g)
	generateSecret :: CPRG g => b -> g -> (Secret b, g)
	calculatePublic :: b -> Secret b -> Public b
	calculateCommon :: b -> Secret b -> Public b -> BS.ByteString

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

instance Base Curve where
	type Param Curve = ()
	type Secret Curve = Integer
	type Public Curve = Point
	generateBase g _ = (secp256r1, g)
	generateSecret _ g = (0x1234567890, g)
	calculatePublic = calculatePublicPoint
	calculateCommon = calculateShared

instance B.Bytable Point where
	fromByteString = Right . decodePublicPoint undefined
	toByteString = encodePublicPoint undefined

calculateShared :: Curve -> Integer -> Point -> BS.ByteString
calculateShared c sn pp =
	let Point x _ = pointMul c sn pp in B.toByteString x

encodePublicPoint :: Curve -> Point -> BS.ByteString
encodePublicPoint _ (Point x y) = B.addLength (undefined :: Word8) .
	BS.cons 4 $ BS.append (B.toByteString x) (B.toByteString y)
encodePublicPoint _ _ = error "TlsServer.encodePublicPoint"

decodePublicPoint :: Curve -> BS.ByteString -> Point
decodePublicPoint _ bs = case BS.uncons $ BS.tail bs of
	Just (4, rest) -> let (x, y) = BS.splitAt 32 rest in
		Point	(either error id $ B.fromByteString x)
			(either error id $ B.fromByteString y)
	_ -> error "TlsServer.decodePublicPoint"

calculatePublicPoint :: Curve -> Integer -> Point
calculatePublicPoint c s = pointMul c s (ecc_g $ common_curve c)

dhparams :: DH.Params
dhparams = unsafePerformIO $ -- do
	readIO =<< readFile "dh-params.txt"
{-
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	let	(ps, _g') = DH.generateParams g 512 2
	return ps
	-}

{-
dhprivate :: Base b => b -> IO (Secret b)
dhprivate b = do
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	let	(pr, _g') = generateSecret g b
	return pr
	-}

decodeParams :: BS.ByteString -> Either String DH.Params
decodeParams = B.evalBytableM $ DH.Params <$> B.take 2 <*> B.take 2

decodePublicNumber :: BS.ByteString -> Either String DH.PublicNumber
decodePublicNumber =
	Right . fromInteger . either error id . B.fromByteString . BS.drop 2

encodeParams :: DH.Params -> BS.ByteString
encodeParams (DH.Params dhP dhG) = BS.concat [
	B.addLength (undefined :: Word16) $ B.toByteString dhP,
	B.addLength (undefined :: Word16) $ B.toByteString dhG
 ]

encodePublicNumber :: DH.PublicNumber -> BS.ByteString
encodePublicNumber =
	B.addLength (undefined :: Word16) . B.toByteString . \(DH.PublicNumber pn) -> pn

instance Base DH.Params where
	type Param DH.Params = (Int, Integer)
	type Secret DH.Params = DH.PrivateNumber
	type Public DH.Params = DH.PublicNumber
	generateBase rng (bits, gen) = DH.generateParams rng bits gen
	generateSecret = flip DH.generatePrivate
	calculatePublic = DH.calculatePublic
	calculateCommon ps sn pn = B.toByteString .
		(\(DH.SharedKey i) -> i) $ DH.getShared ps sn pn

instance B.Bytable DH.Params where
	fromByteString = decodeParams
	toByteString = encodeParams

instance B.Bytable DH.PublicNumber where
	fromByteString = decodePublicNumber
	toByteString = encodePublicNumber

data NoDH = NoDH deriving Show

instance Base NoDH where
	type Param NoDH = ()
	type Secret NoDH = ()
	type Public NoDH = ()
	generateBase = undefined
	generateSecret = undefined
	calculatePublic = undefined
	calculateCommon = undefined

instance B.Bytable NoDH where
	fromByteString = undefined
	toByteString = undefined

instance B.Bytable () where
	fromByteString = undefined
	toByteString = undefined
