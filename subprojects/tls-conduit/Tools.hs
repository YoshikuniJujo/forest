{-# LANGUAGE OverloadedStrings, TupleSections #-}

module Tools (
	bsToLen, lenToBS,
	toLen, fromLen,
	maybeSplitAt,
	eitherSplitAt,
	eitherUncons
) where

import Control.Applicative
import Control.Monad

import Data.Monoid
import Data.Bits
import Data.Word
import qualified Data.ByteString as BS

lenToBS :: Int -> BS.ByteString -> BS.ByteString
lenToBS n bs = fromLen n $ BS.length bs

bsToLen :: Int -> BS.ByteString -> Either String (Int, BS.ByteString)
bsToLen n bs = do
	(len, rest) <- eitherSplitAt "bsToLen" n bs
	(, rest) <$> toLen len

fromLen :: Int -> Int -> BS.ByteString
fromLen n l = BS.pack $ intToWords (n - 1) l

intToWords :: Int -> Int -> [Word8]
intToWords n _ | n < 0 = []
intToWords n l = fromIntegral (l `shiftR` (8 * n)) : intToWords (n - 1) l

toLen :: BS.ByteString -> Either String Int
toLen bs = do
	check "toLen" $ l <= 4
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

eitherSplitAt :: String -> Int -> BS.ByteString -> Either String (BS.ByteString, BS.ByteString)
eitherSplitAt msg n bs = do
	check ("eitherSplitAt: " ++ msg) $ n <= BS.length bs
	return $ BS.splitAt n bs

eitherUncons :: BS.ByteString -> Either String (Word8, BS.ByteString)
eitherUncons = maybe (Left "") Right . BS.uncons

check :: String -> Bool -> Either String ()
check _ True = return ()
check msg False = Left msg

instance Monoid a => MonadPlus (Either a) where
	mzero = Left mempty
	mplus r@(Right _) _ = r
	mplus _ e = e
