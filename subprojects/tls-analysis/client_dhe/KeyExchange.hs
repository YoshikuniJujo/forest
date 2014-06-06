{-# LANGUAGE OverloadedStrings, TypeFamilies, PackageImports #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module KeyExchange (
	ServerKeyExchange(..),
	verifyServerKeyExchange,
	integerToByteString,
	decodeServerKeyExchange,
) where

import GHC.Real

import Control.Applicative
import Control.Arrow
import ByteStringMonad
import qualified Data.ByteString as BS

import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Crypto.Hash.SHA1 as SHA1

import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.Types
import Data.ASN1.Error

import Data.Bits

import qualified Crypto.PubKey.DH as DH
import qualified Crypto.Types.PubKey.DH as DH
import "crypto-random" Crypto.Random

class Base b where
	type Param b
	type Secret b
	type Public b
	generateBase :: CPRG g => g -> Param b -> (b, g)
	generateSecret :: CPRG g => g -> b -> (Secret b, g)
	calculatePublic :: b -> Secret b -> Public b
	calculateCommon :: b -> Secret b -> Public b -> BS.ByteString

	encodeBasePublic :: b -> Public b -> BS.ByteString
	decodeBasePublic :: BS.ByteString -> (b, Public b)
	encodePublic :: b -> Public b -> BS.ByteString
	decodePublic :: b -> BS.ByteString -> Public b

	wantPublic :: b -> Bool
	passPublic :: b -> Bool

instance Base DH.Params where
	type Param DH.Params = (Int, Integer)
	type Secret DH.Params = DH.PrivateNumber
	type Public DH.Params = DH.PublicNumber

	generateBase = uncurry . DH.generateParams
	generateSecret = DH.generatePrivate
	calculatePublic = DH.calculatePublic
	calculateCommon ps sv pv = let
		DH.SharedKey s = DH.getShared ps sv pv in
		integerToByteString s

	encodeBasePublic (DH.Params p g) (DH.PublicNumber y) = BS.concat [
		lenBodyToByteString 2 $ integerToByteString p,
		lenBodyToByteString 2 $ integerToByteString g,
		lenBodyToByteString 2 $ integerToByteString y ]
--	decodeBasePublic = parseParamsPublic

verifyServerKeyExchange :: RSA.PublicKey -> BS.ByteString -> BS.ByteString ->
	ServerKeyExchange -> (BS.ByteString, Either ASN1Error [ASN1])
verifyServerKeyExchange pub cr sr ske@(ServerKeyExchange _ps _ys _ha _sa s "") =
	let	body = BS.concat [cr, sr, getBody ske]
		hash = SHA1.hash body
		unSign = BS.tail . BS.dropWhile (/= 0) . BS.drop 2 $ RSA.ep pub s in
		(hash, decodeASN1' BER unSign)
verifyServerKeyExchange _ _ _ _ = error "verifyServerKeyExchange: bad"

getBody :: ServerKeyExchange -> BS.ByteString
getBody (ServerKeyExchange (DH.Params p g) ys _ha _sa _ "") =
	BS.concat $ map (lenBodyToByteString 2) [
		BS.pack $ toWords p,
		BS.pack $ toWords g,
		BS.pack . toWords $ fromIntegral ys ]
getBody _ = error "bad"

data ServerKeyExchange
	= ServerKeyExchange DH.Params DH.PublicNumber
		Word8 Word8 BS.ByteString
		BS.ByteString
	| ServerKeyExchangeRaw BS.ByteString
	deriving Show

decodeServerKeyExchange :: BS.ByteString -> Either String ServerKeyExchange
decodeServerKeyExchange = evalByteStringM parse

instance Parsable ServerKeyExchange where
	parse = parseServerKeyExchange
	toByteString = serverKeyExchangeToByteString
	listLength _ = Nothing

parseParamsPublic :: ByteStringM (DH.Params, DH.PublicNumber)
parseParamsPublic = do
	dhP <- toI . BS.unpack <$> takeLen 2
	dhG <- toI . BS.unpack <$> takeLen 2
	dhY <- toI . BS.unpack <$> takeLen 2
	return (DH.Params dhP dhG, DH.PublicNumber dhY)

parseServerKeyExchange :: ByteStringM ServerKeyExchange
parseServerKeyExchange = do
	(ps, pn) <- parseParamsPublic
	hashA <- headBS
	sigA <- headBS
	sign <- takeLen 2
	rest <- whole
	return $ ServerKeyExchange ps pn hashA sigA sign rest

serverKeyExchangeToByteString :: ServerKeyExchange -> BS.ByteString
serverKeyExchangeToByteString
	(ServerKeyExchange (DH.Params dhP dhG) dhYs hashA sigA sign rest) =
	BS.concat [
		lenBodyToByteString 2 . BS.pack $ toWords dhP,
		lenBodyToByteString 2 . BS.pack $ toWords dhG,
		lenBodyToByteString 2 . BS.pack . toWords $ fromIntegral dhYs]
	`BS.append`
	BS.pack [hashA, sigA] `BS.append`
	BS.concat [lenBodyToByteString 2 sign, rest]
serverKeyExchangeToByteString (ServerKeyExchangeRaw bs) = bs

toI :: [Word8] -> Integer
toI = wordsToInteger . reverse

wordsToInteger :: [Word8] -> Integer
wordsToInteger [] = 0
wordsToInteger (w : ws) = fromIntegral w .|. (wordsToInteger ws `shiftL` 8)

toWords :: Integer -> [Word8]
toWords = reverse . integerToWords

integerToWords :: Integer -> [Word8]
integerToWords 0 = []
integerToWords i = fromIntegral i : integerToWords (i `shiftR` 8)

instance Integral DH.PublicNumber where
	toInteger pn = case (numerator $ toRational pn, denominator $ toRational pn) of
		(i, 1) -> i
		_ -> error "bad"
	quotRem pn1 pn2 = fromInteger *** fromInteger $
		toInteger pn1 `quotRem` toInteger pn2

instance Integral DH.PrivateNumber where
	toInteger pn = case (numerator $ toRational pn, denominator $ toRational pn) of
		(i, 1) -> i
		_ -> error "bad"
	quotRem pn1 pn2 = fromInteger *** fromInteger $
		toInteger pn1 `quotRem` toInteger pn2

integerToByteString :: Integer -> BS.ByteString
integerToByteString = BS.pack . toWords
