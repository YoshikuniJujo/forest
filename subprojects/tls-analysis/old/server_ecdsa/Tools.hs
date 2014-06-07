{-# LANGUAGE OverloadedStrings #-}

module Tools (
	word64ToByteString,
	byteStringToInt, intToByteString,
	lenBodyToByteString,
) where

import Data.Bits
import Data.Word
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

word64ToByteString :: Word64 -> ByteString
word64ToByteString w64 = BS.replicate (8 - BS.length bs) 0 `BS.append` bs
	where
	bs = BS.reverse $ wtb w64
	wtb 0 = ""
	wtb w = fromIntegral (w .&. 0xff) `BS.cons` wtb (w `shiftR` 8)

byteStringToInt :: ByteString -> Int
byteStringToInt bs = wordsToInt (BS.length bs - 1) $ BS.unpack bs

wordsToInt :: Int -> [Word8] -> Int
wordsToInt n _ | n < 0 = 0
wordsToInt _ [] = 0
wordsToInt n (x : xs) = fromIntegral x `shift` (n * 8) .|. wordsToInt (n - 1) xs

intToByteString :: Int -> Int -> ByteString
intToByteString n = BS.pack . reverse . intToWords n

intToWords :: Int -> Int -> [Word8]
intToWords 0 _ = []
intToWords n i = fromIntegral i : intToWords (n - 1) (i `shiftR` 8)

lenBodyToByteString :: Int -> ByteString -> ByteString
lenBodyToByteString n bs = intToByteString n (BS.length bs) `BS.append` bs
