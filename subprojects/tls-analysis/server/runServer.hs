{-# LANGUAGE OverloadedStrings, PackageImports, ScopedTypeVariables #-}

module Main (main) where

import Control.Applicative ((<$>))
import Control.Concurrent (forkIO)
import Data.List (find)
import System.Environment (getArgs)
import System.Console.GetOpt (getOpt, ArgOrder(..), OptDescr(..), ArgDescr(..))
import System.Exit (exitFailure)
import Network (PortID(..), listenOn, accept)
import TlsServer (
	CipherSuite(..), CipherSuiteKeyEx(..), CipherSuiteMsgEnc(..),
	readRsaKey, readCertificateChain, readCertificateStore)

import ReadEcPrivateKey

import "crypto-random" Crypto.Random
import "monads-tf" Control.Monad.State

import MyServer

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
	g0 :: SystemRNG <- cprgCreate <$> createEntropyPool
	_ <- (`runStateT` g0) $ forever $ do
		(h, _, _) <- liftIO $ accept soc
		g <- StateT $ return . cprgFork
		liftIO . void . forkIO $ server g h cs pk cc pkec ccec mcs
	return ()

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
