{-# LANGUAGE PackageImports, OverloadedStrings, ScopedTypeVariables #-}

import System.Environment
import Control.Applicative
import qualified Data.ByteString as BS
import Data.X509
import Data.X509.File
import Network

import Client

main :: IO ()
main = do
	(svpn :: Int) : _ <- mapM readIO =<< getArgs
	[PrivKeyRSA pkys] <- readKeyFile "yoshikuni.key"
	certChain <- CertificateChain <$> readSignedObject "yoshikuni.crt"
	sv <- connectTo "localhost" . PortNumber $ fromIntegral svpn
	tls <- openTlsServer [(pkys, certChain)] sv
	tPut tls getRequest
	tGetWhole tls >>= print

(+++) :: BS.ByteString -> BS.ByteString -> BS.ByteString
(+++) = BS.append

getRequest :: BS.ByteString
getRequest =
	"GET / HTTP/1.1\r\n" +++
	"Host: localhost:4492\r\n" +++
	"User-Agent: Mozilla/5.0 (X11; Linux i686; rv:24.0) " +++
		"Gecko/20140415 Firefox/24.0\r\n" +++
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;" +++
		"q=0.8\r\n" +++
	"Accept-Language: ja,en-us;q=0.7,en;q=0.3\r\n" +++
	"Accept-Encoding: gzip, deflate\r\n" +++
	"Connection: keep-alive\r\n" +++
	"Cache-Control: max-age=0\r\n\r\n"
