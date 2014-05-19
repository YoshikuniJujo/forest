{-# LANGUAGE ScopedTypeVariables, OverloadedStrings #-}

import Control.Applicative
import Control.Monad
import Control.Concurrent
import System.Environment
import Network

import Server
import MyHandle

main :: IO ()
main = do
	(pn :: Int) : _ <- mapM readIO =<< getArgs
	let port = PortNumber $ fromIntegral pn
	socket <- listenOn port
	forever $ do
		client <- handleToMyHandle . fst3 <$> accept socket
		_ <- forkIO $ httpServer client "Good afternoon, world!\n"
		return ()

fst3 :: (a, b, c) -> a
fst3 (x, y, z) = x
