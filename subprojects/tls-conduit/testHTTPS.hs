{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Data.Conduit.Network
import Content

main :: IO ()
main = runTCPServer (serverSettings 3000 "*") $ \ad -> do
	dat <- readContent ad
	print dat
