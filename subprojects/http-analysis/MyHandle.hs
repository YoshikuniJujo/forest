{-# LANGUAGE OverloadedStrings #-}

module MyHandle (
	MyHandle, handleToMyHandle, mPut, mPutStrLn, mGet, mGetLine,
) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import System.IO

handleToMyHandle :: Handle -> MyHandle
handleToMyHandle h = MyHandle {
	mPut = BS.hPut h,
	mGetLine = BSC.hGetLine h,
	mGet = BSC.hGet h
 }

data MyHandle = MyHandle {
	mPut :: BS.ByteString -> IO (),
	mGetLine :: IO BS.ByteString,
	mGet :: Int -> IO BS.ByteString
 }

mPutStrLn :: MyHandle -> BS.ByteString -> IO ()
mPutStrLn m = mPut m . (`BS.append` "\n")
