module ToByteString (
	lenBodyToByteString
) where

import Data.ByteString (ByteString, append)
import qualified Data.ByteString as BS

import Tools

lenBodyToByteString :: Int -> ByteString -> ByteString
lenBodyToByteString n bs = intToByteString n (BS.length bs) `append` bs
