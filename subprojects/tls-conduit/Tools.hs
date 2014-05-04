module Tools (
	byteStringToInt,
	intToByteString
) where

import Data.Bits
import Data.Word
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS

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