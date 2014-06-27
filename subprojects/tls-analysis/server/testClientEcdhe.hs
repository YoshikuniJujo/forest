{-# LANGUAGE PackageImports #-}

import Control.Applicative
import Control.Concurrent
import "crypto-random" Crypto.Random

import TestClientEcdhe

import ForClientTest

main :: IO ()
main = do
	(cw, sw) <- getPair
	_ <- forkIO $ srv sw
	(_rsk, _rcc, crtS) <- readFiles
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	client g cw crtS
