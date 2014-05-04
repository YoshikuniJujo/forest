{-# LANGUAGE OverloadedStrings #-}

module ToByteString (
	lenBodyToByteString,
	word16ToByteString, word64ToByteString
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

word64ToByteString :: Word64 -> ByteString
word64ToByteString w = BS.replicate (8 - BS.length bs) 0 `BS.append` bs
	where
	bs = BS.reverse $ wtb w
	wtb 0 = ""
	wtb w = fromIntegral (w .&. 0xff) `BS.cons` wtb (w `shiftR` 8)
