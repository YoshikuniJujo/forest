{-# LANGUAGE OverloadedStrings, PackageImports #-}

module Main (main) where

import Control.Applicative ((<$>))
import Control.Monad (forever, void)
import "monads-tf" Control.Monad.State (StateT(..), runStateT, liftIO)
import Control.Concurrent (forkIO)
import System.Environment (getArgs)
import Network (listenOn, accept)
import "crypto-random" Crypto.Random (CPRG(..), SystemRNG, createEntropyPool)
import MyServer (server)
import CommandLine (readCommandLine)

main :: IO ()
main = do
	(prt, css, _td, rsa, ec, mcs) <- readCommandLine =<< getArgs
	soc <- listenOn prt
	g0 <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	void . (`runStateT` g0) . forever $ do
		(h, _, _) <- liftIO $ accept soc
		g <- StateT $ return . cprgFork
		liftIO . forkIO $ server h g css rsa ec mcs
