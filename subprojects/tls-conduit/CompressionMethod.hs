module CompressionMethod (CompressionMethods, compressionMethods) where

import Prelude hiding (take)

import Data.Conduit
import Data.Conduit.Binary

import Data.Word
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

import Tools

compressionMethods :: Monad m => Consumer BS.ByteString m CompressionMethods
compressionMethods = do
	l <- getLen 1
	body <- take l
	return $ map compressionMethod $ LBS.unpack body

type CompressionMethods = [CompressionMethod]

data CompressionMethod
	= CompressionMethodNull
	| CompressionMethod255
	| CompressionMethodOthers Word8
	deriving Show

compressionMethod :: Word8 -> CompressionMethod
compressionMethod 0 = CompressionMethodNull
compressionMethod 255 = CompressionMethod255
compressionMethod w = CompressionMethodOthers w
