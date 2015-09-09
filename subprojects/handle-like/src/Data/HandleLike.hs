{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts #-}

module Data.HandleLike (
	HandleLike(..), hlPutStrLn, DebugHandle(..), Priority) where

import Control.Monad
import Data.Word
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import Data.String

import System.IO

class (Monad (HandleMonad h),
	IsString (DebugLevel h), Ord (DebugLevel h), Bounded (DebugLevel h)) =>
	HandleLike h where
	type HandleMonad h :: * -> *
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
	deriving (Show, Read, Eq, Ord, Enum, Bounded)

instance IsString Priority where
	fromString s = case takeWhile (/= ':') s of
		"low" -> Low
		"high" -> High
		"critical" -> Critical
		_ -> Moderate

bufferSize :: Int
bufferSize = 65536

instance HandleLike Handle where
	type HandleMonad Handle = IO
	hlPut = BS.hPut
	hlGet = BS.hGet
--	hlGetByte h = do [b] <- BS.unpack <$> BS.hGet h 1; return b
	hlGetLine = (chopCR `liftM`) . BS.hGetLine
--	hlGetContent = flip BS.hGet 1
	hlGetContent = flip BS.hGetSome bufferSize
	hlDebug _ Critical = BS.hPutStr stderr
	hlDebug _ _ = const $ return ()
	hlFlush = hFlush
	hlClose = hClose

chopCR :: BS.ByteString -> BS.ByteString
chopCR bs
	| BS.null bs = ""
	| BSC.last bs == '\r' = BSC.init bs
	| otherwise = bs

data DebugHandle h = DebugHandle h (Maybe (DebugLevel h))

instance HandleLike h => HandleLike (DebugHandle h) where
	type HandleMonad (DebugHandle h) = HandleMonad h
	type DebugLevel (DebugHandle h) = DebugLevel h
	hlPut (DebugHandle h _) = hlPut h
	hlGet (DebugHandle h _) = hlGet h
	hlGetByte (DebugHandle h _) = hlGetByte h
	hlGetLine (DebugHandle h _) = hlGetLine h
	hlGetContent (DebugHandle h _) = hlGetContent h
	hlFlush (DebugHandle h _) = hlFlush h
	hlClose (DebugHandle h _) = hlClose h
	hlDebug (DebugHandle _ Nothing) _ = const $ return ()
	hlDebug (DebugHandle h (Just dl0)) dl
		| dl >= dl0 = hlDebug h maxBound
		| otherwise = const $ return ()
	hlError (DebugHandle h _) = hlError h
