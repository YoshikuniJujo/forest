{-# LANGUAGE ScopedTypeVariables, OverloadedStrings #-}

import Control.Applicative
import System.Environment
import Network

import Client
import MyHandle

main :: IO ()
main = do
	(pn :: Int) : _ <- mapM readIO =<< getArgs
	sv <- handleToMyHandle <$> connectTo "localhost"
		(PortNumber $ fromIntegral pn)
	httpClient sv >>= print
