{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module KeyExchange (
	ServerKeyExchange(..),
	verifyServerKeyExchange,
	byteStringToInteger,
	integerToByteString,
	encodePoint,
	EcCurveType(..),
	addSign,
) where

import ByteStringMonad
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Crypto.Hash.SHA1 as SHA1

import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.Types
import Data.ASN1.Error

import Data.Bits

import Parts
import Crypto.Types.PubKey.ECC
-- import EcDhe

verifyServerKeyExchange :: RSA.PublicKey -> BS.ByteString -> BS.ByteString ->
	ServerKeyExchange -> (BS.ByteString, Either ASN1Error [ASN1])
verifyServerKeyExchange pub cr sr ske@(ServerKeyExchange _ _ _ _ s) =
	let	body = BS.concat [cr, sr, getBody ske]
		hash = SHA1.hash body
		unSign = BS.tail . BS.dropWhile (/= 0) . BS.drop 2 $ RSA.ep pub s in
		(hash, decodeASN1' BER unSign)
verifyServerKeyExchange _ _ _ _ = error "verifyServerKeyExchange: bad"

addSign :: RSA.PrivateKey -> BS.ByteString -> BS.ByteString ->
	ServerKeyExchange -> ServerKeyExchange
addSign pk cr sr ske@(ServerKeyExchange ctnc ecp ha sa _) = let
	hash = SHA1.hash $ BS.concat [cr, sr, getBody ske]
	asn1 = [Start Sequence, Start Sequence, OID [1, 3, 14, 3, 2, 26], Null,
		End Sequence, OctetString hash, End Sequence]
	bs = encodeASN1' DER asn1
	pd = BSC.concat [
		"\x00\x01",
		BSC.replicate (125 - BS.length bs) '\xff',
		"\NUL",
		bs
	 ]
	sn = RSA.dp Nothing pk pd in
	ServerKeyExchange ctnc ecp ha sa sn
addSign _ _ _ _ = error "addSign: bad"

getBody :: ServerKeyExchange -> BS.ByteString
getBody (ServerKeyExchange ctnc ecp _ha _sa _sign) =
	BS.concat [ctnc, lenBodyToByteString 1 ecp]
getBody _ = error "bad"

data ServerKeyExchange
	= ServerKeyExchange BS.ByteString BS.ByteString -- (Word8, Point)
		Word8 Word8 BS.ByteString
	| ServerKeyExchangeRaw BS.ByteString
	deriving Show

encodePoint :: Word8 -> Point -> BS.ByteString
encodePoint t (Point x y) =
	t `BS.cons` integerToByteString x `BS.append` integerToByteString y
encodePoint _ _ = error "KeyExchange.encodePoint"

{-
decodePoint :: BS.ByteString -> (Word8, Point)
decodePoint bs = case BS.uncons bs of
	Just (t, rest) -> let (x, y) = BS.splitAt 32 rest in
		(t, Point (toI $ BS.unpack x) (toI $ BS.unpack y))
	_ -> error "KeyExchange.decodePoint"
	-}

instance Parsable ServerKeyExchange where
	parse = parseServerKeyExchange
	toByteString = serverKeyExchangeToByteString
	listLength _ = Nothing

parseServerKeyExchange :: ByteStringM ServerKeyExchange
parseServerKeyExchange = do
	ct <- parse :: ByteStringM EcCurveType
	nc <- parse :: ByteStringM NamedCurve
	ecp <- takeLen 1
--	let (t, p) = decodePoint ecp
	ha <- headBS
	sa <- headBS
	sign <- takeLen 2
	"" <- whole
	return $ ServerKeyExchange
		(toByteString ct `BS.append` toByteString nc) ecp ha sa sign

serverKeyExchangeToByteString :: ServerKeyExchange -> BS.ByteString
serverKeyExchangeToByteString ske@(ServerKeyExchange _ _ ha sa sn) =
	BS.concat [
		getBody ske,
		BS.pack [ha, sa],
		lenBodyToByteString 2 sn
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
