{-# LANGUAGE OverloadedStrings, ScopedTypeVariables #-}

import System.Environment
import Control.Applicative
import Control.Monad
import qualified Data.ByteString as BS
import Data.X509
import Data.X509.File
import Data.X509.CertificateStore
import Network
import TlsClient
import Data.HandleLike

import System.Console.GetOpt
import System.Exit

options :: [OptDescr Option]
options = [
	Option "p" ["pms-ver-err"] (NoArg OptPmsVerErr) "PMS version error",
	Option "" ["hello-version"]
		(ReqArg readOptHelloVersion "version [major].[minor]")
		"client hello version",
	Option "c" ["start-by-change-cipher-spec"]
		(NoArg OptStartByChangeCipherSpec)
		"start by change cipher spec",
	Option "f" ["start-by-finished"]
		(NoArg OptStartByFinished)
		"start by finished",
	Option "" ["client-version"]
		(ReqArg readOptClientVersion "version [major].[minor]")
		"client version",
	Option "e" ["empty-cipher-suite"] (NoArg OptEmptyCipherSuite)
		"empty cipher suite",
	Option "" ["empty-compression-method"] (NoArg OptEmptyCompressionMethod)
		"empty compression method",
	Option "" ["not-client-certificate"] (NoArg OptNotClientCertificate)
		"not client certificate"
 ]

readOptHelloVersion :: String -> Option
readOptHelloVersion (mjr : '.' : mnr : "") =
	OptHelloVersion (read [mjr]) (read [mnr])
readOptHelloVersion _ = error "readOptHelloVersion: bad version expression"

readOptClientVersion :: String -> Option
readOptClientVersion (mjr : '.' : mnr : "") =
	OptClientVersion (read [mjr]) (read [mnr])
readOptClientVersion _ = error "readOptHelloVersion: bad version expression"

(+++) :: BS.ByteString -> BS.ByteString -> BS.ByteString
(+++) = BS.append

main :: IO ()
main = do
	(opts, args, errs) <- getOpt Permute options <$> getArgs
	unless (null errs) $ do
		mapM_ putStr errs
		exitFailure
	print $ OptPmsVerErr `elem` opts
	(svpn :: Int) : _ <- mapM readIO args
	[PrivKeyRSA pkys] <- readKeyFile "yoshikuni.key"
	certChain <- CertificateChain <$> readSignedObject "yoshikuni.crt"
	certStore <- makeCertificateStore <$> readSignedObject "cacert.pem"
	sv <- connectTo "localhost" . PortNumber $ fromIntegral svpn
	tls <- openTlsServer [(pkys, certChain)] certStore sv opts
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
