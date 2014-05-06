{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import System.IO

import Fragment
import Basic

main :: IO ()
main = do
	client <- openFile "client" WriteMode
	server <- openFile "server" WriteMode
	evalTlsIO proc (ClientHandle client) (ServerHandle server)
	hClose client
	hClose server

proc :: TlsIO ()
proc = do
	writeFragment Server $ Fragment (ContentTypeRaw 38) (Version 4 9) "Itsuk"
	writeFragment Client $ Fragment (ContentTypeRaw 95) (Version 3 4) "Manam"
