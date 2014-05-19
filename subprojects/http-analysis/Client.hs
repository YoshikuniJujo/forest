{-# LANGUAGE ScopedTypeVariables, OverloadedStrings #-}

module Client (httpClient) where

import Control.Applicative
import Data.Maybe

import HttpTypes
import HandleLike

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

httpClient :: HandleLike h => h -> IO BS.ByteString
httpClient sv = do
	hlPutStrLn sv request
	src <- hGetHeader sv
	let res = parseResponse src
	cnt <- hlGet sv (contentLength $ responseContentLength res)
	let res' = res { responseBody = cnt }
	mapM_ BSC.putStrLn . catMaybes $ showResponse res'
	return cnt

hGetHeader :: HandleLike h => h -> IO [BS.ByteString]
hGetHeader h = do
	l <- dropCR <$> hlGetLine h
	if (BS.null l) then return [] else (l :) <$> hGetHeader h

dropCR :: BS.ByteString -> BS.ByteString
dropCR s = if BSC.last s == '\r' then BS.init s else s

crlf :: [BS.ByteString] -> BS.ByteString
crlf = BS.concat . map (+++ "\r\n")

request :: BS.ByteString
request = crlf . catMaybes . showRequest . RequestGet (Uri "/") (Version 1 1) $
	Get {
		getHost = Just . Host "localhost" $ Just 8080,
		getUserAgent = Just [Product "Mozilla" (Just "5.0")],
		getAccept = Just [Accept ("text", "plain") (Qvalue 1.0)],
		getAcceptLanguage = Just [AcceptLanguage "ja" (Qvalue 1.0)],
		getAcceptEncoding = Just [],
		getConnection = Just [Connection "close"],
		getCacheControl = Just [MaxAge 0],
		getOthers = []
	 }
