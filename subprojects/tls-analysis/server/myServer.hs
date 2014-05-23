{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Control.Applicative
import Control.Monad
import Control.Concurrent
import System.Environment
import System.Console.GetOpt
import qualified Data.ByteString as BS
import Network
import TlsServer
import HandleLike

main :: IO ()
main = do
	(opts, pn : _, _errs) <- getOpt Permute options <$> getArgs
	let dcc = OptDisableClientCert `notElem` opts
	port <- (PortNumber . fromIntegral <$>) $ (readIO :: String -> IO Int) pn
	pk <- readRsaKey "localhost.key"
	cc <- readCertificateChain "localhost.crt"
	cs <- readCertificateStore ["cacert.pem"]
	soc <- listenOn port
	forever $ do
		(h, _, _) <- accept soc
		void $ forkIO $ do
			cl <- openClient h pk cc $ if dcc then Just cs else Nothing
			hlGetLine cl >>= print
			hlGetLine cl >>= print
			hlGetContent cl >>= print
			hlPut cl answer
			hlClose cl

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
