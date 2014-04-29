{-# LANGUAGE OverloadedStrings #-}

module Version (
	Version,
	version
) where

import Prelude hiding (take)

import Data.Word
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

import Data.Conduit
import Data.Conduit.Binary

data Version = Version Word8 Word8
	deriving Show

version :: Monad m => Consumer BS.ByteString m Version
version = do
	bs <- take 2
	return $ fromBS bs

fromBS :: LBS.ByteString -> Version
fromBS bs = let [vmjr, vmnr] = LBS.unpack bs in Version vmjr vmnr
