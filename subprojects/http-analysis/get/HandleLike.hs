{-# LANGUAGE OverloadedStrings #-}

module HandleLike (
	HandleLike(..), hlPutStrLn
) where

import Control.Applicative
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import System.IO

class HandleLike h where
	hlPut :: h -> BS.ByteString -> IO ()
	hlGet :: h -> Int -> IO BS.ByteString
	hlGetLine :: h -> IO BS.ByteString

instance HandleLike Handle where
	hlPut = BS.hPut
	hlGet = BS.hGet
	hlGetLine = (chopCR <$>) . BS.hGetLine

hlPutStrLn :: HandleLike h => h -> BS.ByteString -> IO ()
hlPutStrLn h = hlPut h . (`BS.append` "\n")

chopCR :: BS.ByteString -> BS.ByteString
chopCR bs
	| BS.null bs = ""
	| BSC.last bs == '\r' = BSC.init bs
	| otherwise = bs
