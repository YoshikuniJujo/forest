{-# LANGUAGE TypeFamilies, PackageImports #-}

module ForClientTest (getPair, readFiles, srv, readFilesEcdsa) where

import Control.Applicative
import Control.Concurrent.STM
import Data.HandleLike
import System.IO
import System.Environment
import "crypto-random" Crypto.Random

import qualified Data.ByteString as BS
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA

import TestServer
import CommandLine
import ReadFile

srv :: ChanHandle -> IO ()
srv sw = do
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	(_prt, cs, rsa, ec, mcs, _td) <- readOptions =<< getArgs
	server g sw cs rsa ec mcs

readFiles :: IO (RSA.PrivateKey, X509.CertificateChain, X509.CertificateStore)
readFiles = (,,)
	<$> readRsaKey "clientFiles/yoshikuni.key"
	<*> readCertificateChain "clientFiles/yoshikuni.crt"
	<*> readCertificateStore ["cacert.pem"]

readFilesEcdsa :: IO
	(ECDSA.PrivateKey, X509.CertificateChain, X509.CertificateStore)
readFilesEcdsa = (,,)
	<$> readEcdsaKey "clientFiles/client_ecdsa.key"
	<*> readCertificateChain "clientFiles/client_ecdsa.cert"
	<*> readCertificateStore ["cacert.pem"]

data ChanHandle = ChanHandle (TChan BS.ByteString) (TChan BS.ByteString)

instance HandleLike ChanHandle where
	type HandleMonad ChanHandle = IO
	hlPut (ChanHandle _ w) = atomically . writeTChan w
	hlGet h@(ChanHandle r _) n = do
		bs <- atomically $ readTChan r
		let l = BS.length bs
		if l < n
			then (bs `BS.append`) <$> hlGet h (n - l)
			else atomically $ do
				let (x, y) = BS.splitAt n bs
				unGetTChan r y
				return x
	hlDebug _ _ = BS.putStr
	hlClose _ = return ()

instance ValidateHandle ChanHandle where
	validate _ = validate (undefined :: Handle)

getPair :: IO (ChanHandle, ChanHandle)
getPair = do
	c1 <- newTChanIO
	c2 <- newTChanIO
	return (ChanHandle c1 c2, ChanHandle c2 c1)
