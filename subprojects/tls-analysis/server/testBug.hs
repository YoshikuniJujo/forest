{-# LANGUAGE TypeFamilies, PackageImports #-}

import Control.Applicative
import Control.Monad
import Control.Concurrent
import "crypto-random" Crypto.Random

import TestClient
import Data.HandleLike

import Control.Concurrent.STM
import qualified Data.ByteString as BS
import ReadFile
import System.IO
import CommandLine
import System.Environment

import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509

import TestServer

cipherSuites :: [CipherSuite]
cipherSuites = [
	CipherSuite ECDHE_ECDSA AES_128_CBC_SHA256,
	CipherSuite ECDHE_ECDSA AES_128_CBC_SHA,
	CipherSuite ECDHE_RSA AES_128_CBC_SHA256,
	CipherSuite ECDHE_RSA AES_128_CBC_SHA,
	CipherSuite DHE_RSA AES_128_CBC_SHA256,
	CipherSuite DHE_RSA AES_128_CBC_SHA,
	CipherSuite RSA AES_128_CBC_SHA256,
	CipherSuite RSA AES_128_CBC_SHA
 ]

ecdhe :: [CipherSuite]
ecdhe = [
	CipherSuite ECDHE_ECDSA AES_128_CBC_SHA256,
	CipherSuite ECDHE_ECDSA AES_128_CBC_SHA,
	CipherSuite ECDHE_RSA AES_128_CBC_SHA256,
	CipherSuite ECDHE_RSA AES_128_CBC_SHA,
	CipherSuite RSA AES_128_CBC_SHA
 ]

len :: Int
len = length ecdhe - 2

main :: IO ()
main = forM_ [1 .. 10] $ \i -> do
	print i
	forM_ (map (`drop` ecdhe) [len, len - 1 .. 0]) runRsa
	forM_ (map (`drop` ecdhe) [len, len - 1 .. 0]) ecdsa

runRsa :: [CipherSuite] -> IO ()
runRsa cs = do
	(cw, sw) <- getPair
	_ <- forkIO $ srv sw cs
	(rsk, rcc, crtS) <- readFiles
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	client g cw [(rsk, rcc)] crtS

ecdsa :: [CipherSuite] -> IO ()
ecdsa cs = do
	(cw, sw) <- getPair
	_ <- forkIO $ srv sw cs
	(rsk, rcc, crtS) <- readFilesEcdsa
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	client g cw [(rsk, rcc)] crtS

srv :: ChanHandle -> [CipherSuite] -> IO ()
srv sw cs = do
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	(_prt, _cs, rsa, ec, mcs, _td) <- readOptions =<< getArgs
	server g sw cs rsa ec mcs

readFiles :: IO (CertSecretKey, X509.CertificateChain, X509.CertificateStore)
readFiles = (,,)
	<$> readKey "clientFiles/yoshikuni.key"
	<*> readCertificateChain "clientFiles/yoshikuni.crt"
	<*> readCertificateStore ["cacert.pem"]

readFilesEcdsa :: IO
	(CertSecretKey, X509.CertificateChain, X509.CertificateStore)
readFilesEcdsa = (,,)
	<$> readKey "clientFiles/client_ecdsa.key"
	<*> readCertificateChain "clientFiles/client_ecdsa.cert"
	<*> readCertificateStore ["cacert.pem"]

data ChanHandle = ChanHandle (TChan BS.ByteString) (TChan BS.ByteString)

instance HandleLike ChanHandle where
	type HandleMonad ChanHandle = IO
	hlPut (ChanHandle _ w) = atomically . writeTChan w
	hlGet h@(ChanHandle r _) n = do
		(b, l, bs) <- atomically $ do
			bs <- readTChan r
			let l = BS.length bs
			if l < n
				then return (True, l, bs)
				else do	let (x, y) = BS.splitAt n bs
					unGetTChan r y
					return (False, l, x)
		if b	then (bs `BS.append`) <$> hlGet h (n - l)
			else return bs
	hlDebug _ _ = BS.putStr
	hlClose _ = return ()

instance ValidateHandle ChanHandle where
	validate _ = validate (undefined :: Handle)

getPair :: IO (ChanHandle, ChanHandle)
getPair = do
	c1 <- newTChanIO
	c2 <- newTChanIO
	return (ChanHandle c1 c2, ChanHandle c2 c1)
