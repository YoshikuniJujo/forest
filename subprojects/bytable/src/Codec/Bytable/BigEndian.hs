{-# OPTIONS_GHC -fno-warn-orphans #-}

module Codec.Bytable.BigEndian () where

import Data.Bits
import Data.Word
import Data.Word.Word24
import Codec.Bytable
import qualified Data.ByteString as BS

instance Bytable Int where
	fromByteString bs
		| BS.length bs <= 4 = Right $ byteStringToNum bs
		| otherwise = Left
			"Codec.Bytable.BigEndian: Bytable Int: too large"
	toByteString = integralToByteStringN 4

instance Bytable Integer where
	fromByteString bs = Right $ byteStringToNum bs
	toByteString = integralToByteString

instance Bytable Word8 where
	fromByteString bs
		| BS.length bs <= 1 = Right $ byteStringToNum bs
		| otherwise = Left
			"Codec.Bytable.BigEndian: Bytable Word8: too large"
	toByteString = integralToByteStringN 1

instance Bytable Word16 where
	fromByteString bs
		| BS.length bs <= 2 = Right $ byteStringToNum bs
		| otherwise = Left
			"Codec.Bytable.BigEndian: Bytable Word16: too large"
	toByteString = integralToByteStringN 2

instance Bytable Word24 where
	fromByteString bs
		| BS.length bs <= 3 = Right $ byteStringToNum bs
		| otherwise = Left
			"Codec.Bytable.BigEndian: Bytable Word24: too large"
	toByteString = integralToByteStringN 3

instance Bytable Word32 where
	fromByteString bs
		| BS.length bs <= 4 = Right $ byteStringToNum bs
		| otherwise = Left
			"Codec.Bytable.BigEndian: Bytable Word32: too large"
	toByteString = integralToByteStringN 4

instance Bytable Word64 where
	fromByteString bs
		| BS.length bs <= 8 = Right $ byteStringToNum bs
		| otherwise = Left
			"Codec.Bytable.BigEndian: Bytable Word32: too large"
	toByteString = integralToByteStringN 8

byteStringToNum :: (Num n, Bits n) => BS.ByteString -> n
byteStringToNum = wordsToNum . reverse . BS.unpack

wordsToNum :: (Num n, Bits n) => [Word8] -> n
wordsToNum [] = 0
wordsToNum (w : ws) = fromIntegral w .|. wordsToNum ws `shiftL` 8

integralToByteString :: (Integral n, Bits n) => n -> BS.ByteString
integralToByteString = BS.pack . reverse . integralToWords

integralToByteStringN :: (Integral n, Bits n) => Int -> n -> BS.ByteString
integralToByteStringN n = BS.pack .
	(\ws -> replicate (n - length ws) 0 ++ ws) .
	reverse . integralToWords

integralToWords :: (Integral n, Bits n) => n -> [Word8]
integralToWords 0 = []
integralToWords n = fromIntegral n : integralToWords (n `shiftR` 8)
