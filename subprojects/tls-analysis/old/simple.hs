{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Control.Concurrent (forkIO)
import Data.Conduit
import Data.Conduit.Network

import qualified Data.ByteString as BS
import Control.Monad.IO.Class

main :: IO ()
main = runTCPServer (serverSettings 4492 "*") $ \ad -> do
	appSource ad $= peek $$ await
--	runTCPClient (clientSettings 443 "localhost") $ \adsv -> do
	runTCPClient (clientSettings 3000 "localhost") $ \adsv -> do
		appSource ad $= peek $$ appSink adsv
		forkIO $ appSource adsv $= peek $$ appSink ad
		return ()

peek :: (Monad m, MonadIO m) => Conduit BS.ByteString m BS.ByteString
peek = do
	mbs <- await
	case mbs of
		Just bs -> do
			liftIO $ print bs
			yield bs
			peek
		_ -> return ()
