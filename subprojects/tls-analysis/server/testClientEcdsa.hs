{-# LANGUAGE TypeFamilies, PackageImports #-}

import Control.Applicative
import Control.Concurrent
import "crypto-random" Crypto.Random

import TestClient

import ForClientTest

main :: IO ()
main = do
	(cw, sw) <- getPair
	_ <- forkIO $ srv sw
	(rsk, rcc, crtS) <- readFilesEcdsa
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	client g cw (rsk, rcc) crtS
