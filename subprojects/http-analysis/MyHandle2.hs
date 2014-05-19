{-# LANGUAGE OverloadedStrings #-}

module MyHandle2 (
	MyHandle, mPut, mPutStrLn, mGet, mGetLine,
	handleToMyHandle, tlsServerToMyHandle,
) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import System.IO
import qualified TlsClient as CL

tlsServerToMyHandle :: CL.TlsServer -> MyHandle
tlsServerToMyHandle tc = MyHandle {
	mPut = CL.tPut tc,
	mGetLine = CL.tGetLine tc,
	mGet = CL.tGet tc
 }

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
