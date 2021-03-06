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
	httpPost tls "I am HTTP over TLS client!\n" >>= print
