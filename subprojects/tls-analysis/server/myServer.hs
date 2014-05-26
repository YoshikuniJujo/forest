{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Control.Applicative
import Control.Monad
import Control.Concurrent
import Data.HandleLike
import System.Environment
import System.Console.GetOpt
import System.Exit
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import Network
import TlsServer

main :: IO ()
main = do
	(opts, pn : _, errs) <- getOpt Permute options <$> getArgs
	unless (null errs) $ mapM_ putStr errs >> exitFailure
	port <- (PortNumber . fromIntegral <$>) (readIO pn :: IO Int)
	pk <- readRsaKey "localhost.key"
	cc <- readCertificateChain "localhost.crt"
	mcs <- if OptDisableClientCert `elem` opts
		then return Nothing
		else Just <$> readCertificateStore ["cacert.pem"]
	soc <- listenOn port
	forever $ do
		(h, _, _) <- accept soc
		void . forkIO $ do
			cl <- openClient h pk cc mcs
			unless (tCheckName cl "Yoshikuni") $ do
				putStrLn "This client is not accepted."
				exitFailure
			untilEmpty (hlGetLine cl) >>= mapM_ BSC.putStrLn
			hlPut cl answer
			hlClose cl
			putStrLn ""

untilEmpty :: IO BS.ByteString -> IO [BS.ByteString]
untilEmpty rd = do
	ln <- rd
	if BS.null ln then return [] else (ln :) <$> untilEmpty rd

data Option = OptDisableClientCert deriving (Show, Eq)

options :: [OptDescr Option]
options = [Option "d" ["disable-client-cert"]
	(NoArg OptDisableClientCert) "disable client certification"]
			
answer :: BS.ByteString
answer = BS.concat [
	"HTTP/1.1 200 OK\r\n",
	"Transfer-Encoding: chunked\r\n",
	"Date: Wed, 07 May 2014 02:27:34 GMT\r\n",
	"Server: Warp/2.1.4\r\n",
	"Content-Type: text/plain\r\n\r\n",
	"004\r\n", "PONC\r\n", "003\r\n", "abc\r\n", "0\r\n\r\n" ]
