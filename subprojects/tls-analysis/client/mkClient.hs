{-# LANGUAGE OverloadedStrings, ScopedTypeVariables #-}

import System.Environment
import Control.Applicative
import qualified Data.ByteString as BS
import Data.X509
import Data.X509.File
import Data.X509.CertificateStore
import Network
import TlsClient
import Data.HandleLike

import Control.Monad
import System.Exit
import System.Console.GetOpt

import Basic

data Option
	= SHA1
	| SHA256
	deriving (Show, Eq)

optDescr :: [OptDescr Option]
optDescr = [
	Option "" ["sha1"] (NoArg SHA1) "Use SHA1",
	Option "" ["sha256"] (NoArg SHA256) "Use SHA256"
 ]

getCipherSuites :: [Option] -> [CipherSuite]
getCipherSuites opts = case (SHA1 `elem` opts, SHA256 `elem` opts) of
	(True, False) -> [TLS_RSA_WITH_AES_128_CBC_SHA]
--	(False, True) -> [TLS_RSA_WITH_AES_128_CBC_SHA256]
	_ -> [	TLS_RSA_WITH_AES_128_CBC_SHA256,
		TLS_RSA_WITH_AES_128_CBC_SHA ]

(+++) :: BS.ByteString -> BS.ByteString -> BS.ByteString
(+++) = BS.append

main :: IO ()
main = do
	(opts, svpna : name : _, errs) <- getOpt Permute optDescr <$> getArgs
	unless (null errs) $ do
		mapM_ putStr errs
		exitFailure
	[PrivKeyRSA pkys] <- readKeyFile "yoshikuni.key"
	certChain <- CertificateChain <$> readSignedObject "yoshikuni.crt"
--	certStore <- makeCertificateStore <$> readSignedObject "cacert.pem"
	certStore <- makeCertificateStore . concat <$> mapM readSignedObject [
		"cacert.pem",
		"../verisign/rsa/veri_test_root_3.pem"
	 ]
	sv <- connectTo "localhost" . PortNumber . fromIntegral =<<
		(readIO svpna :: IO Int)
	let suit = getCipherSuites opts
	tls <- openTlsServer name [(pkys, certChain)] certStore sv suit
	hlPut tls $
		"GET / HTTP/1.1\r\n" +++
		"Host: localhost:4492\r\n" +++
		"User-Agent: Mozilla/5.0 (X11; Linux i686; rv:24.0) " +++
			"Gecko/20140415 Firefox/24.0\r\n" +++
		"Accept: text/html,application/xhtml+xml,application/xml;" +++
			"q=0.9,*/*;q=0.8\r\n" +++
		"Accept-Language: ja,en-us;q=0.7,en;q=0.3\r\n" +++
		"Accept-Encoding: gzip, deflate\r\n" +++
		"Connection: keep-alive\r\n" +++
		"Cache-Control: max-age=0\r\n\r\n"
	hlGetHeaders tls >>= print
	hlGetContent tls >>= print
--	tGet tls 10 >>= print
--	tGet tls 10 >>= print
	{-
	tGetByte tls >>= print
	tGetByte tls >>= print
	tGetByte tls >>= print
	tGetByte tls >>= print
	-}
	tClose tls

hlGetHeaders :: TlsServer -> IO [BS.ByteString]
hlGetHeaders tls = do
	l <- hlGetLine tls
	if BS.null l then return [l] else (l :) <$> hlGetHeaders tls
