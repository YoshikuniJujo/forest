{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module KeyExchange (
	ServerKeyExchange(..),
	verifyServerKeyExchange,
	byteStringToInteger,
	integerToByteString,
	secp256r1,
	encodePoint,
	EcCurveType(..),
	addSign,

	decodeSignature,
) where

import GHC.Real

import Control.Applicative
import Control.Arrow
import ByteStringMonad
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.Types.PubKey.ECDSA as ECDSA
import qualified Crypto.Hash.SHA1 as SHA1

import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.Types
import Data.ASN1.Error

import Data.Bits

-- import Crypto.PubKey.DH

import Parts
import Crypto.Types.PubKey.ECC

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

verifyServerKeyExchange :: RSA.PublicKey -> BS.ByteString -> BS.ByteString ->
	ServerKeyExchange -> (BS.ByteString, Either ASN1Error [ASN1])
verifyServerKeyExchange pub cr sr ske@(ServerKeyExchangeEc _ _ _ _ _ _ s "") =
	let	body = BS.concat $ [cr, sr, getBody ske]
		hash = SHA1.hash body
		unSign = BS.tail . BS.dropWhile (/= 0) . BS.drop 2 $ RSA.ep pub s in
		(hash, decodeASN1' BER unSign)
verifyServerKeyExchange _ _ _ _ = error "verifyServerKeyExchange: bad"

addSign :: ECDSA.PrivateKey -> BS.ByteString -> BS.ByteString ->
	ServerKeyExchange -> ServerKeyExchange
addSign pk cr sr ske@(ServerKeyExchangeEc ct nc t p ha sa _ "") = let
	body = BS.concat $ [cr, sr, getBody ske]
--	asn1 = [Start Sequence, Start Sequence, OID [1, 3, 14, 3, 2, 26], Null,
--		End Sequence, OctetString hash, End Sequence]
--	bs = encodeASN1' DER asn1
{-
	pd = BSC.concat [
		"\x00\x01",
		BSC.replicate (125 - BS.length bs) '\xff',
		"\NUL",
		bs
	 ]
-}

	Just (ECDSA.Signature r s) = ECDSA.signWith 800 pk SHA1.hash body
	sn = encodeEcdsaSign $ EcdsaSign 0x30 (2, r) (2, s) in
	ServerKeyExchangeEc ct nc t p ha sa sn ""
addSign _ _ _ _ = error "addSign: bad"

getBody :: ServerKeyExchange -> BS.ByteString
getBody (ServerKeyExchangeEc ct nc t p ha sa _sign "") =
	BS.concat $ [
		toByteString ct,
		toByteString nc,
		lenBodyToByteString 1 $ encodePoint t p]
getBody _ = error "bad"

data ServerKeyExchange
	= ServerKeyExchangeEc EcCurveType NamedCurve Word8 Point
		Word8 Word8 BS.ByteString
		BS.ByteString
	| ServerKeyExchangeRaw BS.ByteString
	deriving Show

encodePoint :: Word8 -> Point -> BS.ByteString
encodePoint t (Point x y) =
	t `BS.cons` integerToByteString x `BS.append` integerToByteString y

decodePoint :: BS.ByteString -> (Word8, Point)
decodePoint bs = case BS.uncons bs of
	Just (t, rest) -> let (x, y) = BS.splitAt 32 rest in
		(t, Point (toI $ BS.unpack x) (toI $ BS.unpack y))
	_ -> error "KeyExchange:readPoint"

instance Parsable ServerKeyExchange where
	parse = parseServerKeyExchange
	toByteString = serverKeyExchangeToByteString
	listLength _ = Nothing

parseServerKeyExchange :: ByteStringM ServerKeyExchange
parseServerKeyExchange = do
	ct <- parse
	nc <- parse
	ecp <- takeLen 1
	let (t, p) = decodePoint ecp
	ha <- headBS
	sa <- headBS
	sign <- takeLen 2
	rest <- whole
	return $ ServerKeyExchangeEc ct nc t p ha sa sign rest

serverKeyExchangeToByteString :: ServerKeyExchange -> BS.ByteString
serverKeyExchangeToByteString ske@(ServerKeyExchangeEc _ _ _ _ ha sa sn rst) =
	BS.concat [
		getBody ske,
		BS.pack [ha, sa],
		lenBodyToByteString 2 sn,
		rst
	 ]
serverKeyExchangeToByteString (ServerKeyExchangeRaw bs) = bs

byteStringToInteger :: BS.ByteString -> Integer
byteStringToInteger = toI . BS.unpack

toI :: [Word8] -> Integer
toI ws = wordsToInteger $ reverse ws

wordsToInteger :: [Word8] -> Integer
wordsToInteger [] = 0
wordsToInteger (w : ws) = fromIntegral w .|. (wordsToInteger ws `shiftL` 8)

toWords :: Integer -> [Word8]
toWords = reverse . integerToWords

integerToWords :: Integer -> [Word8]
integerToWords 0 = []
integerToWords i = fromIntegral i : integerToWords (i `shiftR` 8)

{-
instance Integral PublicNumber where
	toInteger pn = case (numerator $ toRational pn, denominator $ toRational pn) of
		(i, 1) -> i
		_ -> error "bad"
	quotRem pn1 pn2 = fromInteger *** fromInteger $
		toInteger pn1 `quotRem` toInteger pn2

instance Integral PrivateNumber where
	toInteger pn = case (numerator $ toRational pn, denominator $ toRational pn) of
		(i, 1) -> i
		_ -> error "bad"
	quotRem pn1 pn2 = fromInteger *** fromInteger $
		toInteger pn1 `quotRem` toInteger pn2
		-}

integerToByteString :: Integer -> BS.ByteString
integerToByteString = BS.pack . toWords

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

data EcdsaSign
	= EcdsaSign Word8 (Word8, Integer) (Word8, Integer)
	deriving Show

encodeEcdsaSign :: EcdsaSign -> BS.ByteString
encodeEcdsaSign (EcdsaSign t (rt, rb) (st, sb)) = BS.concat [
	BS.pack [t, len rbbs + len sbbs + 4],
	BS.pack [rt, len rbbs], rbbs,
	BS.pack [st, len sbbs], sbbs ]
	where
	len = fromIntegral . BS.length
	rbbs = integerToByteString rb
	sbbs = integerToByteString sb

decodeSignature :: BS.ByteString -> ECDSA.Signature
decodeSignature bs = let
	Right [Start Sequence, IntVal r, IntVal s, End Sequence] = decodeASN1' DER bs
		in ECDSA.Signature r s
