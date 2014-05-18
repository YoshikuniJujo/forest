{-# LANGUAGE ScopedTypeVariables #-}

import Control.Concurrent
import Control.Applicative
import Control.Monad
import Data.Maybe
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
			mapM_ putStrLn h
			putStrLn ""
			print $ parse h
			putStrLn ""
			mapM_ putStrLn . catMaybes . showRequest $ parse h
			putStrLn ""
			putStr answer'
			hPutStrLn client answer'
		return ()

hGetHeader :: Handle -> IO [String]
hGetHeader h = do
	l <- dropCR <$> hGetLine h
	if (null l) then return [] else (l :) <$> hGetHeader h

dropCR :: String -> String
dropCR s = if last s == '\r' then init s else s

crlf :: [String] -> String
crlf = concatMap (++ "\r\n")

answer' :: String
answer' = crlf . showResponse $ Response {
	responseVersion = Version 1 1,
	responseStatusCode = OK,
	responseDate = readTime defaultTimeLocale
		"%a, %d %b %Y %H:%M:%S" "Wed, 07 May 2014 02:27:34",
	responseContentLength = ContentLength 13,
	responseContentType = ContentType ("text", "plain"),
	responseOthers = [],
	responseBody = "Hello, world!"
 }
