{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Control.Monad

import Data.Conduit.Network
import Content

import Data.Conduit
import Data.Conduit.Binary

import Data.ByteString.Lazy (toStrict)

main :: IO ()
main = runTCPServer (serverSettings 3000 "*") $ \ad -> do
--	dat <- readContent ad
	bs <- fragment ad
	Just dat <- sourceLbs bs $$ parseContent =$ await
	print dat
	when (toStrict bs /= contentToByteString dat) $ do
		print bs
		print $ contentToByteString dat
