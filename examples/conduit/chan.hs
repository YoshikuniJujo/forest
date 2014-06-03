{-# LANGUAGE OverloadedStrings #-}

import Prelude hiding (map)

import Control.Monad
import Control.Concurrent.STM
import Control.Concurrent (forkIO)

import Data.Conduit
import Data.Conduit.List
import Data.Conduit.Binary
import Data.Conduit.TMChan
import Data.ByteString (ByteString, append)
import Data.ByteString.Char8 (pack)

import System.IO
import System.IO.Unsafe

main :: IO ()
main = do
	chan <- atomically newTMChan
	forkIO $ forever $ do
		str <- getLine
		atomically $ writeTMChan chan $ pack str
	sourceTMChan chan
		=$= map (`append` "\n")
		=$= checkQuit
		$$ sinkHandle stdout

checkQuit :: Monad m => Conduit ByteString m ByteString
checkQuit = do
	ms <- await
	case ms of
		Just "quit\n" -> return ()
		Just s -> do
			yield s
			checkQuit
		_ -> return ()
