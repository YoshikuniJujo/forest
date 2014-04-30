{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Control.Concurrent

import Network

import Control.Monad

import Data.Conduit.Network
import Content

import Data.Conduit
import qualified Data.Conduit.List as List
import Data.Conduit.Binary

import Data.ByteString.Lazy (toStrict, fromStrict)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

import System.IO

main :: IO ()
main = runTCPServer (serverSettings 3000 "*") $ \ad -> do
--	dat <- readContent ad
	bs <- fragment ad
	Just dat <- sourceLbs bs $$ parseContent =$ await
	print dat
	when (toStrict bs /= contentToByteString dat) $ do
		print bs
		print $ contentToByteString dat
	runTCPClient (clientSettings 443 "localhost") $ \adsv -> do
		sourceLbs (fromStrict $ contentToByteString dat) $$ appSink adsv
--		appSource adsv $$ List.map (BSC.pack . show) =$
--			conduitHandle stdout =$ appSink ad
		forkIO $ appSource adsv $$ appSink ad
		appSource ad $$ appSink adsv
--	sv <- connectTo "localhost" $ PortNumber 443
--	putStrLn "connected"
--	hSetBuffering sv NoBuffering
--	BS.hPutStr sv $ contentToByteString dat
--	BS.hGetContents sv >>= print
--	hGetContents sv >>= print
