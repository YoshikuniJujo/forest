{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Control.Applicative ((<$>))
import Control.Monad (forever, unless, void)
import Control.Concurrent (forkIO)
import Data.Maybe (fromMaybe)
import Data.HandleLike (HandleLike(..))
import System.Environment (getArgs)
import System.Console.GetOpt (getOpt, ArgOrder(..), OptDescr(..), ArgDescr(..))
import System.Exit (exitFailure)
import Network (PortID(..), listenOn, accept)
import TlsServer (
	withClient, getName,
	readRsaKey, readCertificateChain, readCertificateStore)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

import ReadEcPrivateKey

main :: IO ()
main = do
	(opts, pn : _, errs) <- getOpt Permute options <$> getArgs
	unless (null errs) $ mapM_ putStr errs >> exitFailure
	port <- (PortNumber . fromIntegral <$>) (readIO pn :: IO Int)
	pk <- readEcPrivKey "localhost_ecdsa.key"
	cc <- readCertificateChain "localhost_ecdsa.cert"
	mcs <- if OptDisableClientCert `elem` opts
		then return Nothing
		else Just <$> readCertificateStore ["cacert.pem"]
	soc <- listenOn port
	forever $ do
		(h, _, _) <- accept soc
		void . forkIO . withClient h pk cc mcs $ \cl -> do
			doUntil BS.null (hlGetLine cl) >>= mapM_ BSC.putStrLn
			hlPut cl . answer . fromMaybe "Anonym" $ getName cl

data Option = OptDisableClientCert deriving (Show, Eq)

options :: [OptDescr Option]
options = [Option "d" ["disable-client-cert"]
	(NoArg OptDisableClientCert) "disable client certification"]
			
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
