{-# LANGUAGE OverloadedStrings, PackageImports, TypeFamilies #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module KeyExchange (
	Base(..), SecretKey(..),

	integerToByteString,
	byteStringToInteger,

	decodeSignature,

	ServerKeyExchange(..),
	addSign,
	serverKeyExchangeToByteString,
) where

import Data.Bits
import Data.ASN1.Types
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import "crypto-random" Crypto.Random

import qualified Data.ByteString as BS
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA

-- import Content
import ByteStringMonad
import Parts

import qualified Crypto.PubKey.ECC.ECDSA as ECDSA

class SecretKey sk where
	sign :: sk -> (BS.ByteString -> BS.ByteString) ->
		BS.ByteString -> BS.ByteString
	signatureAlgorithm :: sk -> SignatureAlgorithm

instance SecretKey ECDSA.PrivateKey where
	sign sk hs bs = let
		Just (ECDSA.Signature r s) = ECDSA.signWith 4649 sk hs bs in
		encodeEcdsaSign $ EcdsaSign 0x30 (2, r) (2, s)
	signatureAlgorithm _ = SignatureAlgorithmEcdsa

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

instance SecretKey RSA.PrivateKey where
	sign sk hs bs = let
		h = hs bs
		a = [Start Sequence, Start Sequence, OID [1, 3, 14, 3, 2, 26],
			Null, End Sequence, OctetString h, End Sequence]
		b = encodeASN1' DER a
		pd = BS.concat [
			"\x00\x01", BS.replicate (125 - BS.length b) 0xff,
			"\NUL", b ] in
		RSA.dp Nothing sk pd
	signatureAlgorithm _ = SignatureAlgorithmRsa

addSign :: SecretKey sk =>
	sk -> ByteString -> ByteString -> ServerKeyExchange -> ServerKeyExchange
addSign sk cr sr (ServerKeyExchange ps ys ha sa _) = let
	sn = sign sk SHA1.hash $ BS.concat [cr, sr, ps, ys] in
	ServerKeyExchange ps ys ha sa sn

data ServerKeyExchange
--	= ServerKeyExchange ByteString ByteString Word8 Word8 BS.ByteString
	= ServerKeyExchange ByteString ByteString HashAlgorithm SignatureAlgorithm BS.ByteString
	deriving Show

serverKeyExchangeToByteString :: ServerKeyExchange -> BS.ByteString
serverKeyExchangeToByteString
	(ServerKeyExchange params dhYs hashA sigA sn) =
	BS.concat [
		params, dhYs, toByteString hashA, toByteString sigA,
		lenBodyToByteString 2 sn ]

wordsToInteger :: [Word8] -> Integer
wordsToInteger [] = 0
wordsToInteger (w : ws) = fromIntegral w .|. (wordsToInteger ws `shiftL` 8)

integerToWords :: Integer -> [Word8]
integerToWords 0 = []
integerToWords i = fromIntegral i : integerToWords (i `shiftR` 8)

integerToByteString :: Integer -> BS.ByteString
integerToByteString = BS.pack . reverse . integerToWords

byteStringToInteger :: BS.ByteString -> Integer
byteStringToInteger = wordsToInteger . reverse . BS.unpack

class Base b where
	type Param b
	type Secret b
	type Public b
	generateBase :: CPRG g => g -> Param b -> (b, g)
	generateSecret :: CPRG g => g -> b -> (Secret b, g)
	calculatePublic :: b -> Secret b -> Public b
	calculateCommon :: b -> Secret b -> Public b -> BS.ByteString

	encodeBase :: b -> BS.ByteString
	decodeBase :: BS.ByteString -> b
	encodePublic :: b -> Public b -> BS.ByteString
	decodePublic :: b -> BS.ByteString -> Public b

decodeSignature :: BS.ByteString -> ECDSA.Signature
decodeSignature bs = let
	Right [Start Sequence, IntVal r, IntVal s, End Sequence] = decodeASN1' DER bs
		in ECDSA.Signature r s
