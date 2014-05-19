{-# LANGUAGE ScopedTypeVariables, OverloadedStrings #-}

import Control.Applicative
import Control.Monad
import Control.Concurrent
import qualified Data.ByteString as BS
import Data.X509
import Data.X509.File
import Data.X509.CertificateStore
import System.Environment
import Network

import TlsServer
import Server
import HandleLike

main :: IO ()
main = do
	(pn :: Int) : _ <- mapM readIO =<< getArgs
	certChain <- CertificateChain <$> readSignedObject "localhost.crt"
	[PrivKeyRSA pk] <- readKeyFile "localhost.key"
	certStore <- makeCertificateStore <$> readSignedObject "cacert.pem"
	let pcl = PortNumber $ fromIntegral pn
	scl <- listenOn pcl
	forever $ do
		(cl, _, _) <- accept scl
		_ <- forkIO $ do
			tls <- openTlsClient True certStore certChain pk cl
			httpServer tls "Hello, world!\n" >>= print
--			hlGetLine tls >>= print
--			hlPut tls answer
		return ()

answer :: BS.ByteString
answer = BS.concat [
	"HTTP/1.1 200 OK\r\n",
	"Transfer-Encoding: chunked\r\n",
	"Date: Wed, 07 May 2014 02:27:34 GMT\r\n",
	"Server: Warp/2.1.4\r\n",
	"Content-Type: text/plain\r\n\r\n",
	"004\r\n",
	"PONC\r\n",
	"003\r\n",
	"abc\r\n",
	"0\r\n\r\n"
 ]
