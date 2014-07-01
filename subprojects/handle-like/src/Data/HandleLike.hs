{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts #-}

module Data.HandleLike (HandleLike(..), hlPutStrLn) where

import Control.Monad
import Data.Word
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import Data.String

import System.IO

class (Monad (HandleMonad h),
	IsString (DebugLevel h), Ord (DebugLevel h)) =>
	HandleLike h where
	type HandleMonad h
	type DebugLevel h
	hlPut :: h -> BS.ByteString -> HandleMonad h ()
	hlGet :: h -> Int -> HandleMonad h BS.ByteString
	hlGetByte :: h -> HandleMonad h Word8
	hlGetLine :: h -> HandleMonad h BS.ByteString
	hlGetContent :: h -> HandleMonad h BS.ByteString
	hlFlush :: h -> HandleMonad h ()
	hlClose :: h -> HandleMonad h ()
	hlDebug :: h -> DebugLevel h -> BS.ByteString -> HandleMonad h ()
	hlError :: h -> BS.ByteString -> HandleMonad h a

	type DebugLevel h = Priority
	hlGetByte h = do [b] <- BS.unpack `liftM` hlGet h 1; return b
	hlGetLine h = do
		b <- hlGetByte h
		case b of
			10 -> return ""
			_ -> BS.cons b `liftM` hlGetLine h
	hlGetContent = flip hlGet 1
	hlFlush _ = return ()
	hlDebug _ _ _ = return ()
	hlError _ msg = error $ BSC.unpack msg

hlPutStrLn :: HandleLike h => h -> BS.ByteString -> HandleMonad h ()
hlPutStrLn h = hlPut h . (`BS.append` "\n")

data Priority = Low | Moderate | High | Critical
	deriving (Show, Read, Eq, Ord, Enum)

instance IsString Priority where
	fromString s = case takeWhile (/= ':') s of
		"low" -> Low
		"high" -> High
		"critical" -> Critical
		_ -> Moderate

instance HandleLike Handle where
	type HandleMonad Handle = IO
	hlPut = BS.hPut
	hlGet = BS.hGet
--	hlGetByte h = do [b] <- BS.unpack <$> BS.hGet h 1; return b
	hlGetLine = (chopCR `liftM`) . BS.hGetLine
--	hlGetContent = flip BS.hGet 1
	hlDebug _ Critical = BS.hPutStr stderr
	hlDebug _ _ = const $ return ()
	hlFlush = hFlush
	hlClose = hClose

chopCR :: BS.ByteString -> BS.ByteString
chopCR bs
	| BS.null bs = ""
	| BSC.last bs == '\r' = BSC.init bs
	| otherwise = bs
