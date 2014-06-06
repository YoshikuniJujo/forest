{-# LANGUAGE PackageImports, TypeFamilies #-}

module DiffieHellman (
	Base(..),
	toWords,
	parseParamsPublic,
	integerToByteString,
) where

import Control.Applicative
import Data.Bits

import qualified Data.ByteString as BS
import qualified Crypto.Types.PubKey.DH as DH
import qualified Crypto.PubKey.DH as DH

import "crypto-random" Crypto.Random

import ByteStringMonad

class Base b where
	type Param b
	type Secret b
	type Public b
	generateBase :: CPRG g => g -> Param b -> (b, g)
	generateSecret :: CPRG g => g -> b -> (Secret b, g)
	calculatePublic :: b -> Secret b -> Public b
	calculateCommon :: b -> Secret b -> Public b -> BS.ByteString

	encodeBasePublic :: b -> Public b -> BS.ByteString
	decodeBasePublic :: BS.ByteString -> Either String ((b, Public b), BS.ByteString)
	encodePublic :: b -> Public b -> BS.ByteString
	decodePublic :: b -> BS.ByteString -> Either String (Public b)

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
	decodeBasePublic = runByteStringM parseParamsPublic
	encodePublic _ = dhEncodePublic
	decodePublic _ = evalByteStringM $
		DH.PublicNumber . byteStringToInteger <$> takeLen 2

	wantPublic _ = True
	passPublic _ = True

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

integerToByteString :: Integer -> BS.ByteString
integerToByteString = BS.pack . toWords

byteStringToInteger :: BS.ByteString -> Integer
byteStringToInteger = toI . BS.unpack

dhEncodePublic :: DH.PublicNumber -> BS.ByteString
dhEncodePublic =
	lenBodyToByteString 2 . integerToByteString .  (\(DH.PublicNumber pn) -> pn)

parseParamsPublic :: ByteStringM (DH.Params, DH.PublicNumber)
parseParamsPublic = do
	dhP <- toI . BS.unpack <$> takeLen 2
	dhG <- toI . BS.unpack <$> takeLen 2
	dhY <- toI . BS.unpack <$> takeLen 2
	return (DH.Params dhP dhG, DH.PublicNumber dhY)
