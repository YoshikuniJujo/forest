{-# LANGUAGE OverloadedStrings, RankNTypes #-}

module Tools (getLen, maybeLen) where

import Prelude hiding (take)
import Control.Applicative
import Data.Conduit
import Data.Conduit.Binary

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
	if LBS.length bs < fromIntegral n
		then return Nothing
		else return $ Just $ toLen bs
