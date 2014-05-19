{-# LANGUAGE OverloadedStrings #-}

module HandleLike (
	HandleLike(..), hlPutStrLn
) where

import qualified Data.ByteString as BS
import System.IO

class HandleLike h where
	hlPut :: h -> BS.ByteString -> IO ()
	hlGet :: h -> Int -> IO BS.ByteString
	hlGetLine :: h -> IO BS.ByteString

instance HandleLike Handle where
	hlPut = BS.hPut
	hlGet = BS.hGet
	hlGetLine = BS.hGetLine

hlPutStrLn :: HandleLike h => h -> BS.ByteString -> IO ()
hlPutStrLn h = hlPut h . (`BS.append` "\n")
