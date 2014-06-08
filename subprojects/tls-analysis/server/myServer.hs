{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Control.Applicative ((<$>))
import Control.Monad (forever, unless, void)
import Control.Concurrent (forkIO)
import Data.Maybe (fromMaybe)
import Data.List (find)
import Data.HandleLike (HandleLike(..))
import System.Environment (getArgs)
import System.Console.GetOpt (getOpt, ArgOrder(..), OptDescr(..), ArgDescr(..))
import System.Exit (exitFailure)
import Network (PortID(..), listenOn, accept)
import TlsServer (
	ValidateHandle(..),
	CipherSuite(..), CipherSuiteKeyEx(..), CipherSuiteMsgEnc(..),
	withClient, getName, openClientSt,
	readRsaKey, readCertificateChain, readCertificateStore)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

import ReadEcPrivateKey

main :: IO ()
main = do
	(opts, pn : kfp : cfp: _, errs) <- getOpt Permute options <$> getArgs
	unless (null errs) $ mapM_ putStr errs >> exitFailure
	port <- (PortNumber . fromIntegral <$>) (readIO pn :: IO Int)
	pk <- readRsaKey kfp
	cc <- readCertificateChain cfp
	pkec <- readEcPrivKey "localhost_ecdsa.key"
	ccec <- readCertificateChain "localhost_ecdsa.cert"
	mcs <- if OptDisableClientCert `elem` opts
		then return Nothing
		else Just <$> readCertificateStore ["cacert.pem"]
	soc <- listenOn port
	let cs = optsToCipherSuites opts
	forever $ do
		(h, _, _) <- accept soc
		void . forkIO . withClient h cs pk cc (pkec, ccec) mcs $
			\cl -> do
				doUntil BS.null (hlGetLine cl) >>=
					mapM_ BSC.putStrLn
				hlPut cl . answer . fromMaybe "Anonym" $ getName cl

data Option
	= OptDisableClientCert
	| OptLevel CipherSuiteLevel
	deriving (Show, Eq)

isLevel :: Option -> Bool
isLevel (OptLevel _) = True
isLevel _ = False

data CipherSuiteLevel
	= ToEcdsa256
	| ToEcdsa
	| ToEcdhe256
	| ToEcdhe
	| ToDhe256
	| ToDhe
	| ToRsa256
	| ToRsa
	| NoLevel
	deriving (Show, Eq, Enum)

optsToCipherSuites :: [Option] -> [CipherSuite]
optsToCipherSuites opts = case find isLevel opts of
	Just (OptLevel l) -> leveledCipherSuites l
	_ -> cipherSuites

leveledCipherSuites :: CipherSuiteLevel -> [CipherSuite]
leveledCipherSuites l = drop (fromEnum l) cipherSuites

cipherSuites :: [CipherSuite]
cipherSuites = [
	CipherSuite ECDHE_ECDSA AES_128_CBC_SHA256,
	CipherSuite ECDHE_ECDSA AES_128_CBC_SHA,
	CipherSuite ECDHE_RSA AES_128_CBC_SHA256,
	CipherSuite ECDHE_RSA AES_128_CBC_SHA,
	CipherSuite DHE_RSA AES_128_CBC_SHA256,
	CipherSuite DHE_RSA AES_128_CBC_SHA,
	CipherSuite RSA AES_128_CBC_SHA256,
	CipherSuite RSA AES_128_CBC_SHA ]

readCipherSuiteLevel :: String -> CipherSuiteLevel
readCipherSuiteLevel "ecdsa256" = ToEcdsa256
readCipherSuiteLevel "ecdsa" = ToEcdsa
readCipherSuiteLevel "ecdhe256" = ToEcdhe256
readCipherSuiteLevel "ecdhe" = ToEcdhe
readCipherSuiteLevel "dhe256" = ToDhe256
readCipherSuiteLevel "dhe" = ToDhe
readCipherSuiteLevel "rsa256" = ToRsa256
readCipherSuiteLevel "rsa" = ToRsa
readCipherSuiteLevel _ = NoLevel

options :: [OptDescr Option]
options = [
	Option "d" ["disable-client-cert"]
		(NoArg OptDisableClientCert) "disable client certification",
	Option "l" ["level"]
		(ReqArg (OptLevel . readCipherSuiteLevel) "cipher suite level")
		"set cipher suite level"
 ]
			
answer :: String -> BS.ByteString
answer name = BS.concat [
	"HTTP/1.1 200 OK\r\n", "Transfer-Encoding: chunked\r\n",
	"Date: Wed, 07 May 2014 02:27:34 GMT\r\n", "Server: Warp/2.1.4\r\n",
	"Content-Type: text/plain\r\n\r\n",
	"007\r\n", "Hello, \r\n",
	BSC.pack . show $ length name, "\r\n", BSC.pack name, "\r\n",
	"001\r\n", "!\r\n",
	"0\r\n\r\n" ]

doUntil :: (a -> Bool) -> IO a -> IO [a]
doUntil p rd = (\x -> if p x then return [x] else (x :) <$> doUntil p rd) =<< rd
