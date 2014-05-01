{-# LANGUAGE OverloadedStrings, TupleSections #-}

module Tools (
	bsToLen, lenToBS,
	toLen, fromLen,
	maybeSplitAt,
	eitherSplitAt,
	eitherUncons,
	word16ToWords, wordsToWord16,
	check,
	getBody,
	bodyToBS,
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

word16ToWords :: Word16 -> [Word8]
word16ToWords w = [fromIntegral $ w `shiftR` 8, fromIntegral w]

wordsToWord16 :: [Word8] -> Word16
wordsToWord16 [w1, w2] = fromIntegral w1 `shift` 8 .|. fromIntegral w2
wordsToWord16 _ = error "wordsToWord16: bad word list"

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

getBody :: Int -> BS.ByteString -> Either String (BS.ByteString, BS.ByteString)
getBody n src = do
	(len, src') <- bsToLen n src
	eitherSplitAt "getBody" len src'

bodyToBS :: Int -> BS.ByteString -> BS.ByteString
bodyToBS n body = lenToBS n body `BS.append` body
