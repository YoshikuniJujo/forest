{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Control.Concurrent (forkIO)
import Control.Monad.IO.Class

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
main = runTCPServer (serverSettings 4492 "*") $ \ad -> do
--	dat <- readContent ad
	bs <- fragment ad
	Just dat <- sourceLbs bs $$ parseContent =$ await
	print dat
	putStrLn ""
	when (toStrict bs /= contentToByteString dat) $ do
		print bs
		print $ contentToByteString dat
	runTCPClient (clientSettings 443 "localhost") $ \adsv -> do
		sourceLbs (fromStrict $ contentToByteString dat) $$ appSink adsv
--		appSource adsv $$ List.map (BSC.pack . show) =$
--			conduitHandle stdout =$ appSink ad
		forkIO $ serverToClient adsv ad -- $ appSource adsv $$ appSink ad
		appSource ad $$ appSink adsv
--	sv <- connectTo "localhost" $ PortNumber 443
--	putStrLn "connected"
--	hSetBuffering sv NoBuffering
--	BS.hPutStr sv $ contentToByteString dat
--	BS.hGetContents sv >>= print
--	hGetContents sv >>= print

serverToClient :: AppData -> AppData -> IO ()
serverToClient adsv ad = appSource adsv $= peek $$ appSink ad
	
peek :: (Monad m, MonadIO m) => Conduit BS.ByteString m BS.ByteString
peek = do
	mbs <- await
	case mbs of
		Just bs -> do
--			liftIO $ print bs
			ss <- sourceLbs (fromStrict bs) $= parseContent $$ await
			liftIO $ do
				print ss
				putStrLn ""
			yield bs
			peek
		_ -> return ()
