module ToByteString (
	lenBodyToByteString,
	word16ToByteString
) where

import Data.Bits
import Data.Word
import Data.ByteString (ByteString, append, pack)
import qualified Data.ByteString as BS

import Tools

lenBodyToByteString :: Int -> ByteString -> ByteString
lenBodyToByteString n bs = intToByteString n (BS.length bs) `append` bs

word16ToByteString :: Word16 -> ByteString
word16ToByteString w = pack [fromIntegral (w `shiftR` 8), fromIntegral w]
