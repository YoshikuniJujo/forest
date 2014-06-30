{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Data.HandleLike.Instance.Handle () where

import Control.Monad
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import System.IO
import Data.HandleLike.Class

instance HandleLike Handle where
	type HandleMonad Handle = IO
	hlPut = BS.hPut
	hlGet = BS.hGet
--	hlGetByte h = do [b] <- BS.unpack <$> BS.hGet h 1; return b
	hlGetLine = (chopCR `liftM`) . BS.hGetLine
--	hlGetContent = flip BS.hGet 1
	hlDebug _ _ = BS.hPutStr stderr
	hlFlush = hFlush
	hlClose = hClose

chopCR :: BS.ByteString -> BS.ByteString
chopCR bs
	| BS.null bs = ""
	| BSC.last bs == '\r' = BSC.init bs
	| otherwise = bs
