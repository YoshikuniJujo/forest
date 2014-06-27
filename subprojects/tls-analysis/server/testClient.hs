{-# LANGUAGE TypeFamilies, PackageImports #-}

import Control.Applicative
import Control.Monad
import Control.Concurrent
import "crypto-random" Crypto.Random

import TestClient

import ForClientTest

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

len :: Int
len = length cipherSuites - 1

main :: IO ()
main = do
	forM_ (map (flip drop cipherSuites) [len, len - 1 .. 0]) rsa
	forM_ (map (flip drop cipherSuites) [len, len - 1 .. 0]) ecdsa

rsa :: [CipherSuite] -> IO ()
rsa cs = do
	(cw, sw) <- getPair
	_ <- forkIO $ srv sw cs
	(rsk, rcc, crtS) <- readFiles
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	client g cw (rsk, rcc) crtS

ecdsa :: [CipherSuite] -> IO ()
ecdsa cs = do
	(cw, sw) <- getPair
	_ <- forkIO $ srv sw cs
	(rsk, rcc, crtS) <- readFilesEcdsa
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	client g cw (rsk, rcc) crtS
