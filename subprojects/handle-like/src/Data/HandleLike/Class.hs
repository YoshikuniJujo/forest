{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts #-}

module Data.HandleLike.Class (
	HandleLike(..),
	Priority(..),
	hlPutStrLn ) where

import Control.Monad
import Data.Word
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import Data.String

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
