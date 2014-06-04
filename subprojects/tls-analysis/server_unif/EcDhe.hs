{-# LANGUAGE TypeFamilies #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module EcDhe (Curve) where

import Crypto.Types.PubKey.ECC
import Crypto.PubKey.ECC.Prim
import Parts
import qualified Data.ByteString as BS
import KeyExchange
-- import Base
import Data.Word

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
	generateSecret g _ = (0x1234567890, g)
	calculatePublic = calculatePublicPoint
	calculateCommon = calculateShared

	encodeBase = encodeCurve
	decodeBase = undefined
	encodePublic = encodePublicPoint
	decodePublic = decodePublicPoint

calculateShared :: Curve -> Integer -> Point -> BS.ByteString
calculateShared c sn pp =
	let Point x _ = pointMul c sn pp in integerToByteString x

encodePublicPoint :: Curve -> Point -> BS.ByteString
encodePublicPoint _ (Point x y) = lenBodyToByteString 1 .
	BS.cons 4 $ BS.append (integerToByteString x) (integerToByteString y)
encodePublicPoint _ _ = error "TlsServer.encodePublicPoint"

decodePublicPoint :: Curve -> BS.ByteString -> Point
decodePublicPoint _ bs = case BS.uncons $ BS.tail bs of
	Just (4, rest) -> let (x, y) = BS.splitAt 32 rest in
		Point (byteStringToInteger x) (byteStringToInteger y)
	_ -> error "TlsServer.decodePublicPoint"

calculatePublicPoint :: Curve -> Integer -> Point
calculatePublicPoint c s = pointMul c s (ecc_g $ common_curve c)

encodeCurve :: Curve -> BS.ByteString
encodeCurve c
	| c == secp256r1 =
		toByteString NamedCurve `BS.append` toByteString Secp256r1
	| otherwise = error "TlsServer.encodeCurve: not implemented"

data EcCurveType
	= ExplicitPrime
	| ExplicitChar2
	| NamedCurve
	| EcCurveTypeRaw Word8
	deriving Show

instance Parsable EcCurveType where
	parse = do
		w <- headBS
		return $ case w of
			1 -> ExplicitPrime
			2 -> ExplicitChar2
			3 -> NamedCurve
			_ -> EcCurveTypeRaw w
	toByteString ExplicitPrime = BS.pack [1]
	toByteString ExplicitChar2 = BS.pack [2]
	toByteString NamedCurve = BS.pack [3]
	toByteString (EcCurveTypeRaw w) = BS.pack [w]
	listLength _ = Nothing
