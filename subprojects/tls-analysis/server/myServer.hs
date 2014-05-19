{-# LANGUAGE PackageImports, OverloadedStrings #-}

module Main (main) where

import Control.Applicative
import Control.Monad
import Control.Concurrent
import System.Environment
import System.IO
import Data.X509.File
import Data.X509

import Network

import Basic

import qualified Data.ByteString as BS

import Data.X509.CertificateStore

import Crypto.PubKey.RSA

import System.Console.GetOpt

import TlsServer
import MyHandle

options :: [OptDescr Option]
options = [
	Option "d" ["disable-client-cert"] (NoArg OptDisableClientCert)
		"disable client certification" ]

data Option
	= OptDisableClientCert
	deriving (Show, Eq)

main :: IO ()
main = do
	certChain <- CertificateChain <$> readSignedObject "localhost.crt"
	[PrivKeyRSA pk] <- readKeyFile "localhost.key"
	certStore <- makeCertificateStore <$> readSignedObject "cacert.pem"
	(opts, args, _errs) <- getOpt Permute options <$> getArgs
	let doClientCert = OptDisableClientCert `notElem` opts
	[pcl] <- mapM ((PortNumber . fromInt <$>) . readIO) args
	scl <- listenOn pcl
	forever $ do
		client <- fst3 <$> accept scl
		_ <- forkIO $ do
			run' doClientCert certStore certChain pk client
		return ()

run' :: Bool -> CertificateStore -> CertificateChain ->
	PrivateKey -> Handle -> IO ()
run' dcc certStore certChain pk cl = do
	tls <- tlsClientToMyHandle <$>
		openTlsClient dcc certStore certChain pk cl
--	tGetByte tls >>= putStrLn . ("tGetByte: " ++) . show
--	tGet tls 5 >>= print
--	tGetLine tls >>= print
	mGetLine tls >>= print
	mPut tls answer
			
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
