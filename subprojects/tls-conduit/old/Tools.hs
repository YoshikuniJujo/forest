{-# LANGUAGE OverloadedStrings, RankNTypes #-}

module Tools (getLen, maybeLen, lenToBS) where

import Prelude hiding (take)
import Control.Applicative
import Data.Conduit
import Data.Conduit.Binary

import Data.Word
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

toLen :: LBS.ByteString -> Int
toLen bs = let
	ws = map fromIntegral $ LBS.unpack bs in
	mkOne (LBS.length bs - 1) ws
	where
	mkOne _ [] = 0
	mkOne n (x : xs) = x * 256 ^ n + mkOne (n - 1) xs

getLen :: Monad m => Int -> Consumer BS.ByteString m Int
getLen n = toLen <$> take n

maybeLen :: Monad m => Int -> Consumer BS.ByteString m (Maybe Int)
maybeLen n = do
	bs <- take n
	return $ if LBS.length bs < fromIntegral n
		then Nothing
		else Just $ toLen bs

lenToBS :: Int -> Int -> BS.ByteString
lenToBS n = BS.pack . toWords (n - 1)

toWords :: Int -> Int -> [Word8]
toWords n _ | n < 0 = []
toWords n x = fromIntegral (x `div` 256 ^ n) : toWords (n - 1) (x `mod` 256 ^ n)
