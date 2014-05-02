{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import System.IO

import Fragment
import Basic

main :: IO ()
main = do
	client <- openFile "client" ReadMode
	server <- openFile "server" ReadMode
	evalTlsIO proc (ClientHandle client) (ServerHandle server)

proc :: TlsIO ()
proc = do
	fs <- readFragment Server
	fc <- readFragment Client
	liftIO $ print fs
	liftIO $ print fc
