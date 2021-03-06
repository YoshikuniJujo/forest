{-# LANGUAGE ScopedTypeVariables, OverloadedStrings #-}

import System.Environment
import Network

import Client

main :: IO ()
main = do
	(pn :: Int) : _ <- mapM readIO =<< getArgs
	sv <- connectTo "localhost" (PortNumber $ fromIntegral pn)
	httpGet sv >>= print
