{-# LANGUAGE OverloadedStrings, PackageImports, ScopedTypeVariables,
 	TypeFamilies #-}

module Main (main) where

import Control.Monad (forever, void)
import "monads-tf" Control.Monad.State (StateT(..), runStateT, liftIO)
import Control.Concurrent (forkIO)
import System.Environment (getArgs)
import Network (listenOn, accept)
import "crypto-random" Crypto.Random (SystemRNG, CPRG(..), createTestEntropyPool)
import MyServer (server, ValidateHandle(..))
import CommandLine (readCommandLine)

import Data.HandleLike
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import System.IO
import Numeric

main :: IO ()
main = do
	(port, css, rsa, ec, mcs) <- readCommandLine =<< getArgs
	soc <- listenOn port
	let g0 :: SystemRNG = cprgCreate $ createTestEntropyPool "Yoshikuni"
	h <- openFile "test.clt" ReadMode
	server (TestHandle h) g0 css rsa ec mcs
	{-
	void . (`runStateT` g0) . forever $ do
		(h, _, _) <- liftIO $ accept soc
		g <- StateT $ return . cprgFork
		liftIO . forkIO $ server (DebugHandle h) g css rsa ec mcs
		-}

newtype TestHandle = TestHandle Handle deriving Show

instance HandleLike TestHandle where
	type HandleMonad TestHandle = IO
	hlPut (TestHandle h) bs = do
		BSC.putStrLn $ hexdump bs
--		BS.appendFile "test.srv" bs
--		hlPut h bs
	hlGet (TestHandle h) n = do
		BS.hGet h n
--		bs <- hlGet h n
--		BSC.putStrLn $ hexdump bs
--		BS.appendFile "test.clt" bs
--		return bs
	hlClose (TestHandle h) = hlClose h
	hlDebug (TestHandle h) = hlDebug h

instance ValidateHandle TestHandle where
	vldt'' (TestHandle h) = vldt'' h

hexdump :: BS.ByteString -> BS.ByteString
hexdump = BSC.unlines . map (BSC.pack . unwords)
	. separate 16 . map (toTwo . (`showHex` "")) . BS.unpack

toTwo :: String -> String
toTwo s = replicate (2 - length s) '0' ++ s

separate :: Int -> [a] -> [[a]]
separate _ [] = []
separate n xs = take n xs : separate n (drop n xs)
