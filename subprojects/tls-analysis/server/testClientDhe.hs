{-# LANGUAGE PackageImports #-}

import Control.Applicative
import Control.Concurrent
import "crypto-random" Crypto.Random

import TestClientDhe

import ForClientTest

main :: IO ()
main = do
	(cw, sw) <- getPair
	_ <- forkIO $ srv sw
	(rsk, rcc, crtS) <- readFiles
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	client g cw (rsk, rcc) crtS
