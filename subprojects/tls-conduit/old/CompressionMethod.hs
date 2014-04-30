{-# LANGUAGE OverloadedStrings #-}

module CompressionMethod (
	CompressionMethods,
	compressionMethods,
	compressionMethodsToByteString,
	CompressionMethod,
	parseCompressionMethod) where

import Prelude hiding (take, head)

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

parseCompressionMethod :: Monad m => Consumer BS.ByteString m CompressionMethod
parseCompressionMethod = do
	mw <- head
	case mw of
		Just w -> return $ compressionMethod w
		_ -> error "parseCompressionMethod"

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

compressionMethodsToByteString :: CompressionMethods -> BS.ByteString
compressionMethodsToByteString cms =
	lenToBS 1 (length cms) `BS.append`
	BS.concat (map compressionMethodToByteString cms)

compressionMethodToByteString CompressionMethodNull = "\x00"
compressionMethodToByteString _ = error "not implemented"
