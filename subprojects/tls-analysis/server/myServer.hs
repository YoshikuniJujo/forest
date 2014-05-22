{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Control.Applicative
import Control.Monad
import Control.Concurrent
import System.Environment
import System.Console.GetOpt
import qualified Data.ByteString as BS
import Data.X509
import Data.X509.File
import Data.X509.CertificateStore
import Network
import TlsServer
import HandleLike

main :: IO ()
main = do
	certChain <- CertificateChain <$> readSignedObject "localhost.crt"
	[PrivKeyRSA pk] <- readKeyFile "localhost.key"
	certStore <- makeCertificateStore <$> readSignedObject "cacert.pem"
	(opts, args, _errs) <- getOpt Permute options <$> getArgs
	let dcc = OptDisableClientCert `notElem` opts
	[port] <- forM args $
		(PortNumber . fromIntegral <$>) . (readIO :: String -> IO Int)
	soc <- listenOn port
	forever $ do
		(client, _, _) <- accept soc
		void $ forkIO $ do
			tls <- openTlsClient dcc certStore certChain pk client
			hlGetLine tls >>= print
			hlGetLine tls >>= print
			hlGetContent tls >>= print
			hlPut tls answer
			hlClose tls

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
