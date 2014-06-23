{-# LANGUAGE PackageImports #-}

module Main (main) where

import Control.Applicative ((<$>))
import Control.Monad (void, forever)
import "monads-tf" Control.Monad.State (StateT(..), runStateT, liftIO)
import Control.Concurrent (forkIO)
import System.Environment (getArgs)
import Network (listenOn, accept)
import "crypto-random" Crypto.Random (CPRG(..), SystemRNG, createEntropyPool)
import TestServer (server)
import CommandLine (readOptions)

main :: IO ()
main = do
	(prt, cs, rsa, ec, mcs, _td) <- readOptions =<< getArgs
	g0 <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	soc <- listenOn prt
	void . (`runStateT` g0) . forever $ do
		(h, _, _) <- liftIO $ accept soc
		g <- StateT $ return . cprgFork
		liftIO . forkIO $ server g h cs rsa ec mcs
