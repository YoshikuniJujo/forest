{-# LANGUAGE ScopedTypeVariables, OverloadedStrings #-}

import Control.Applicative
import qualified Data.ByteString as BS
import Data.X509
import Data.X509.File
import System.Environment
import Network

import HandleLike
import TlsClient
import Client

(+++) :: BS.ByteString -> BS.ByteString -> BS.ByteString
(+++) = BS.append

main :: IO ()
main = do
	(svpn :: Int) : _ <- mapM readIO =<< getArgs
	[PrivKeyRSA pkys] <- readKeyFile "yoshikuni.key"
	certChain <- CertificateChain <$> readSignedObject "yoshikuni.crt"
	sv <- connectTo "localhost" . PortNumber $ fromIntegral svpn
	tls <- openTlsServer [(pkys, certChain)] sv
	httpClient tls >>= print
	{-
	hlPut tls $
		"GET / HTTP/1.1\r\n" +++
		"Host: localhost:4492\r\n" +++
		"User-Agent: Mozilla/5.0\r\n" +++
		"Accept: text/plain\r\n" +++
		"Accept-Language: ja\r\n" +++
		"Accept-Encoding:\r\n" +++
		"Connection: close\r\n" +++
		"Cache-Control: max-age=0\r\n\r\n"
	hlGetLine tls >>= print
	hlGetLine tls >>= print
	-}
