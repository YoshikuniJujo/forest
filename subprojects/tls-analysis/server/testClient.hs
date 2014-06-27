{-# LANGUAGE TypeFamilies, PackageImports #-}

import Control.Applicative
import Control.Concurrent.STM
import Control.Concurrent
import Data.HandleLike
import System.IO
import System.Environment
import "crypto-random" Crypto.Random

import qualified Data.ByteString as BS

import TestServer
import TestClient
import CommandLine
import ReadFile

main :: IO ()
main = do
	crtS <- readCertificateStore ["cacert.pem"]
	(_prt, cs, rsa, ec, mcs, _td) <- readOptions =<< getArgs
	g0 <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	(cw, sw) <- getPair
	_ <- forkIO $ server g0 sw cs rsa ec mcs
	client g0 cw crtS

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
