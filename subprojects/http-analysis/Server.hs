{-# LANGUAGE ScopedTypeVariables, OverloadedStrings #-}

module Server (httpServer) where

import Control.Applicative
import Data.Maybe
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import Data.Time
import System.IO
import System.Locale

import HttpTypes

httpServer :: Handle -> BS.ByteString -> IO ()
httpServer cl cnt = do
	h <- hGetHeader cl
	mapM_ BSC.putStrLn . catMaybes . showRequest $ parse h
	BSC.hPutStrLn cl . crlf . catMaybes . showResponse $ mkContents cnt

mkContents :: BS.ByteString -> Response
mkContents cnt = Response {
	responseVersion = Version 1 1,
	responseStatusCode = OK,
	responseDate = readTime defaultTimeLocale
		"%a, %d %b %Y %H:%M:%S" "Wed, 07 May 2014 02:27:34",
	responseContentLength = ContentLength $ BS.length cnt,
	responseContentType = ContentType ("text", "plain"),
	responseServer = Nothing,
	responseLastModified = Nothing,
	responseETag = Nothing,
	responseAcceptRanges = Nothing,
	responseConnection = Nothing,
	responseOthers = [],
	responseBody = cnt
 }

hGetHeader :: Handle -> IO [BS.ByteString]
hGetHeader h = do
	l <- dropCR <$> BS.hGetLine h
	print l
	if (BS.null l) then return [] else (l :) <$> hGetHeader h

dropCR :: BS.ByteString -> BS.ByteString
dropCR s = if BSC.last s == '\r' then BS.init s else s

crlf :: [BS.ByteString] -> BS.ByteString
crlf = BS.concat . map (+++ "\r\n")
