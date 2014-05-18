{-# LANGUAGE ScopedTypeVariables #-}

import Control.Applicative
import Control.Monad
import Data.Maybe
import System.IO
import System.Environment
import Network

import HttpTypes

import qualified Data.ByteString as BS

main :: IO ()
main = do
	(pn :: Int) : _ <- mapM readIO =<< getArgs
	sv <- connectTo "localhost" . PortNumber $ fromIntegral pn
	putStr $ request
	hPutStrLn sv request
	src <- hGetHeader sv
	mapM_ putStrLn src
	let res = parseResponse src
	print res
	BS.hGet sv (contentLength $ responseContentLength res) >>= print
	putStrLn ""
--	replicateM_ 15 $ hGetLine sv >>= print

hGetHeader :: Handle -> IO [String]
hGetHeader h = do
	l <- dropCR <$> hGetLine h
	if (null l) then return [] else (l :) <$> hGetHeader h

dropCR :: String -> String
dropCR s = if last s == '\r' then init s else s

crlf :: [String] -> String
crlf = concatMap (++ "\r\n")

request :: String
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
