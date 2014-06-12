{-# LANGUAGE OverloadedStrings, PackageImports, ScopedTypeVariables #-}

module Main (main) where

import Control.Applicative ((<$>))
import Control.Monad (forever, void)
import "monads-tf" Control.Monad.State (StateT(..), runStateT, liftIO)
import Control.Concurrent (forkIO)
import System.Environment (getArgs)
import Network (listenOn, accept)
import "crypto-random" Crypto.Random (SystemRNG, CPRG(..), createEntropyPool)
import MyServer (server)
import CommandLine (readCommandLine)

main :: IO ()
main = do
	(port, css, _tstd, rsa, ec, mcs) <- readCommandLine =<< getArgs
	soc <- listenOn port
	g0 :: SystemRNG <- cprgCreate <$> createEntropyPool
	void . (`runStateT` g0) . forever $ do
		(h, _, _) <- liftIO $ accept soc
		g <- StateT $ return . cprgFork
		liftIO . forkIO $ server h g css rsa ec mcs
