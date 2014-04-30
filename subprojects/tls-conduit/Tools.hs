{-# LANGUAGE OverloadedStrings #-}

module Tools (
	toLen, fromLen,
	maybeSplitAt,
) where

import Control.Monad

import Data.Bits
import Data.Word
import qualified Data.ByteString as BS

fromLen :: Int -> Int -> BS.ByteString
fromLen n l = BS.pack $ intToWords (n - 1) l

intToWords :: Int -> Int -> [Word8]
intToWords n _ | n < 0 = []
intToWords n l = fromIntegral (l `shiftR` (8 * n)) : intToWords (n - 1) l

toLen :: BS.ByteString -> Maybe Int
toLen bs = do
	guard $ l <= 4
	return $ ti (l - 1) $ map fromIntegral $ BS.unpack bs
	where
	l = BS.length bs
	ti n _ | n < 0 = 0
	ti _ [] = 0
	ti n (w : ws) = w `shift` (n * 8) .|. ti (n - 1) ws

maybeSplitAt :: Int -> BS.ByteString -> Maybe (BS.ByteString, BS.ByteString)
maybeSplitAt n bs = do
	guard $ n <= BS.length bs
	return $ BS.splitAt n bs
