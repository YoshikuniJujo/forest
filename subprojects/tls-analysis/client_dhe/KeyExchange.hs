{-# LANGUAGE OverloadedStrings #-}
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

import Crypto.PubKey.DH

verifyServerKeyExchange :: RSA.PublicKey -> BS.ByteString -> BS.ByteString ->
	ServerKeyExchange -> (BS.ByteString, Either ASN1Error [ASN1])
verifyServerKeyExchange pub cr sr ske@(ServerKeyExchange _ps _ys _ha _sa s "") =
	let	body = BS.concat [cr, sr, getBody ske]
		hash = SHA1.hash body
		unSign = BS.tail . BS.dropWhile (/= 0) . BS.drop 2 $ RSA.ep pub s in
		(hash, decodeASN1' BER unSign)
verifyServerKeyExchange _ _ _ _ = error "verifyServerKeyExchange: bad"

getBody :: ServerKeyExchange -> BS.ByteString
getBody (ServerKeyExchange (Params p g) ys _ha _sa _ "") =
	BS.concat $ map (lenBodyToByteString 2) [
		BS.pack $ toWords p,
		BS.pack $ toWords g,
		BS.pack . toWords $ fromIntegral ys ]
getBody _ = error "bad"

data ServerKeyExchange
	= ServerKeyExchange Params PublicNumber
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

parseServerKeyExchange :: ByteStringM ServerKeyExchange
parseServerKeyExchange = do
	(_dhPl, dhP) <- toI . BS.unpack <$> takeLen 2
	(_dhGl, dhG) <- toI . BS.unpack <$> takeLen 2
	(_dhYsl, dhYs) <- toI . BS.unpack <$> takeLen 2
	hashA <- headBS
	sigA <- headBS
	sign <- takeLen 2
	rest <- whole
	return $ ServerKeyExchange
		(Params dhP dhG) (fromInteger dhYs) hashA sigA sign rest

serverKeyExchangeToByteString :: ServerKeyExchange -> BS.ByteString
serverKeyExchangeToByteString
	(ServerKeyExchange (Params dhP dhG) dhYs hashA sigA sign rest) =
	BS.concat [
		lenBodyToByteString 2 . BS.pack $ toWords dhP,
		lenBodyToByteString 2 . BS.pack $ toWords dhG,
		lenBodyToByteString 2 . BS.pack . toWords $ fromIntegral dhYs]
	`BS.append`
	BS.pack [hashA, sigA] `BS.append`
	BS.concat [lenBodyToByteString 2 sign, rest]
serverKeyExchangeToByteString (ServerKeyExchangeRaw bs) = bs

toI :: [Word8] -> (Int, Integer)
toI ws = (length ws, wordsToInteger $ reverse ws)

wordsToInteger :: [Word8] -> Integer
wordsToInteger [] = 0
wordsToInteger (w : ws) = fromIntegral w .|. (wordsToInteger ws `shiftL` 8)

toWords :: Integer -> [Word8]
toWords = reverse . integerToWords

integerToWords :: Integer -> [Word8]
integerToWords 0 = []
integerToWords i = fromIntegral i : integerToWords (i `shiftR` 8)

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

integerToByteString :: Integer -> BS.ByteString
integerToByteString = BS.pack . toWords
