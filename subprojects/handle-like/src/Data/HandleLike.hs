{-# LANGUAGE OverloadedStrings #-}

module Data.HandleLike (HandleLike(..), hlPutStrLn) where

import Control.Applicative
import Data.Word
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import System.IO

class HandleLike h where
	hlPut :: h -> BS.ByteString -> IO ()
	hlGet :: h -> Int -> IO BS.ByteString
	hlGetByte :: h -> IO Word8
	hlGetLine :: h -> IO BS.ByteString
	hlGetContent :: h -> IO BS.ByteString
	hlClose :: h -> IO ()

	hlGetByte h = do [b] <- BS.unpack <$> hlGet h 1; return b
	hlGetLine h = do
		b <- hlGetByte h
		case b of
			10 -> return ""
			_ -> BS.cons b <$> hlGetLine h
	hlGetContent = flip hlGet 1

instance HandleLike Handle where
	hlPut = BS.hPut
	hlGet = BS.hGet
--	hlGetByte h = do [b] <- BS.unpack <$> BS.hGet h 1; return b
	hlGetLine = (chopCR <$>) . BS.hGetLine
--	hlGetContent = flip BS.hGet 1
	hlClose = hClose

hlPutStrLn :: HandleLike h => h -> BS.ByteString -> IO ()
hlPutStrLn h = hlPut h . (`BS.append` "\n")

chopCR :: BS.ByteString -> BS.ByteString
chopCR bs
	| BS.null bs = ""
	| BSC.last bs == '\r' = BSC.init bs
	| otherwise = bs
