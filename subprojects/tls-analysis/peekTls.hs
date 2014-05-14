{-# LANGUAGE PackageImports #-}

import System.Environment
import System.IO
import Control.Concurrent
import Control.Monad
import Data.IORef
import Data.X509
import Data.X509.File
import Network
import "crypto-random" Crypto.Random
-- import Crypto.PubKey.RSA

import Fragment
import Content

main :: IO ()
main = do
	cidRef <- newIORef 0
	clpn : svpn : _ <- getArgs
	[PrivKeyRSA pk] <- readKeyFile "localhost.key"
	sock <- listenOn . PortNumber . fromIntegral $ read clpn
	forever $ do
		cid <- readIORef cidRef
		modifyIORef cidRef succ
		(cl, _, _) <- accept sock
		ep <- createEntropyPool
		sv <- connectTo "localhost" (PortNumber . fromIntegral $ read svpn)
		let	client = ClientHandle cl
			server = ServerHandle sv
		forkIO $ do
			evalTlsIO run ep cid client server pk
			forkIO $ evalTlsIO c2s ep cid client server pk
			evalTlsIO s2c ep cid client server pk

run, c2s, s2c :: TlsIO Content ()
run = return ()

c2s = forever $ do
	f <- readRawFragment Client
	liftIO . putStrLn $ "CLIENT: " ++ take 60 (show f) ++ "..."
	writeRawFragment Server f

s2c = forever $ do
	f <- readRawFragment Server
	liftIO . putStrLn $ "SERVER: " ++ take 60 (show f) ++ "..."
	writeRawFragment Client f
