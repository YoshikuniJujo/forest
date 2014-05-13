module Tools (
	byteStringToInt,
	intToByteString,
	showKey, showKeySingle,
	fromInt,
	fst3
) where

import Data.Bits
import Data.Word
import Data.ByteString (ByteString, unpack)
import qualified Data.ByteString as BS

import Numeric

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

showKeySingle :: ByteString -> String
showKeySingle = unwords . map showH . unpack

showKey :: ByteString -> String
showKey = unlines . map (('\t' :) . unwords) . separateN 16 . map showH . unpack
	where
	separateN _ [] = []
	separateN n xs = take n xs : separateN n (drop n xs)

showH :: Word8 -> String
showH w = let s = showHex w "" in replicate (2 - length s) '0' ++ s

fromInt :: Integral i => Int -> i
fromInt = fromIntegral

fst3 :: (a, b, c) -> a
fst3 (x, _, _) = x
