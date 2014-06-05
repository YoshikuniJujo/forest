{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module KeyExchange (
	ServerKeyExchange(..),
	verifyServerKeyExchange,
	integerToByteString,
	byteStringToInteger,
	secp256r1,
	encodePoint,
) where

import ByteStringMonad
import Data.Maybe
import qualified Data.ByteString as BS

import qualified Crypto.Hash.SHA1 as SHA1

import Data.ASN1.Types
import Data.ASN1.Error

import Data.Bits

-- import Crypto.PubKey.DH

import Parts
import Crypto.Types.PubKey.ECC

import qualified Crypto.PubKey.ECC.ECDSA as ECDSA

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

data EcdsaSign
	= EcdsaSign Word8 (Word8, Integer) (Word8, Integer)
	deriving Show

decodeEcdsaSign :: BS.ByteString -> EcdsaSign
decodeEcdsaSign bs = fromJust $ do
	(rt, rest) <- BS.uncons rs
	(rl, rest') <- BS.uncons rest
	let (rb, rest'') = BS.splitAt (fromIntegral rl) rest'
	(st, rest''') <- BS.uncons rest''
	(sl, rest'''') <- BS.uncons rest'''
	let (sb, "") = BS.splitAt (fromIntegral sl) rest''''
	return $ EcdsaSign t
		(rt, byteStringToInteger rb)
		(st, byteStringToInteger sb)
	where
	(h, rs) = BS.splitAt 2 bs
	[t, _l] = BS.unpack h

decodeSignature :: BS.ByteString -> ECDSA.Signature
decodeSignature bs = let EcdsaSign _ (_, r) (_, s) = decodeEcdsaSign bs in
	ECDSA.Signature r s

verifyServerKeyExchange :: ECDSA.PublicKey -> BS.ByteString -> BS.ByteString ->
	ServerKeyExchange -> (BS.ByteString, Either ASN1Error [ASN1], ECDSA.Signature, Bool)
verifyServerKeyExchange pub cr sr ske@(ServerKeyExchangeEc _ _ _ _ _ _ s "") =
	let	body = BS.concat [cr, sr, getBody ske]
		hash = SHA1.hash body
		sign = decodeSignature s in
		(hash, Right [], sign, ECDSA.verify SHA1.hash pub sign body)
verifyServerKeyExchange _ _ _ _ = error "verifyServerKeyExchange: bad"

getBody :: ServerKeyExchange -> BS.ByteString
getBody (ServerKeyExchangeEc ct nc t p _ha _sa _sign "") =
	BS.concat [
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
encodePoint _ PointO = error "KeyExchange.encodePoint"

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
	ha <- headBS "8"
	sa <- headBS "9"
	sign <- takeLen 2
	rest <- whole
	return $ ServerKeyExchangeEc ct nc t p ha sa sign rest
{- do
	(dhPl, dhP) <- toI . BS.unpack <$> takeLen 2
	(dhGl, dhG) <- toI . BS.unpack <$> takeLen 2
	(dhYsl, dhYs) <- toI . BS.unpack <$> takeLen 2
	hashA <- headBS
	sigA <- headBS
	sign <- takeLen 2
	rest <- whole
	return $ ServerKeyExchange
		(Params dhP dhG) (fromInteger dhYs) hashA sigA sign rest
		-}

serverKeyExchangeToByteString :: ServerKeyExchange -> BS.ByteString
{-
serverKeyExchangeToByteString
	(ServerKeyExchange (Params dhP dhG) dhYs hashA sigA sign rest) =
	BS.concat [
		lenBodyToByteString 2 . BS.pack $ toWords dhP,
		lenBodyToByteString 2 . BS.pack $ toWords dhG,
		lenBodyToByteString 2 . BS.pack . toWords $ fromIntegral dhYs]
	`BS.append`
	BS.pack [hashA, sigA] `BS.append`
	BS.concat [lenBodyToByteString 2 sign, rest]
	-}
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
		w <- headBS "7"
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
