{-# LANGUAGE ScopedTypeVariables, OverloadedStrings #-}

import Control.Concurrent
import Control.Applicative
import Control.Monad
import Data.Maybe
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import Data.Time
import System.IO
import System.Environment
import System.Locale
import Network

import HttpTypes

main :: IO ()
main = do
	(pn :: Int) : _ <- mapM readIO =<< getArgs
	let port = PortNumber $ fromIntegral pn
	socket <- listenOn port
	forever $ do
		(client, _, _) <- accept socket
		_ <- forkIO $ do
			h <- hGetHeader client
			mapM_ BSC.putStrLn h
			BSC.putStrLn ""
			print $ parse h
			BSC.putStrLn ""
			mapM_ BSC.putStrLn . catMaybes . showRequest $ parse h
			BSC.putStrLn ""
			BS.putStr answer'
			BSC.hPutStrLn client answer'
		return ()

hGetHeader :: Handle -> IO [BS.ByteString]
hGetHeader h = do
	l <- dropCR <$> BS.hGetLine h
	print l
	if (BS.null l) then return [] else (l :) <$> hGetHeader h

dropCR :: BS.ByteString -> BS.ByteString
dropCR s = if BSC.last s == '\r' then BS.init s else s

crlf :: [BS.ByteString] -> BS.ByteString
crlf = BS.concat . map (+++ "\r\n")

answer' :: BS.ByteString
answer' = crlf . catMaybes . showResponse $ Response {
	responseVersion = Version 1 1,
	responseStatusCode = OK,
	responseDate = readTime defaultTimeLocale
		"%a, %d %b %Y %H:%M:%S" "Wed, 07 May 2014 02:27:34",
	responseContentLength = ContentLength 13,
	responseContentType = ContentType ("text", "plain"),
	responseServer = Nothing,
	responseLastModified = Nothing,
	responseETag = Nothing,
	responseAcceptRanges = Nothing,
	responseConnection = Nothing,
	responseOthers = [],
	responseBody = "Hello, world!"
 }
