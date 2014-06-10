{-# LANGUAGE OverloadedStrings, PackageImports, ScopedTypeVariables,
 	TypeFamilies #-}

module Main (main) where

import Control.Monad (forever, void, unless, forM_)
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

import System.Directory

import Random

import System.FilePath
import Control.Applicative
import Data.List

main :: IO ()
main = do
	(port, _css, rsa, ec, mcs) <- readCommandLine =<< getArgs
	soc <- listenOn port
	let g0 :: StdGen = cprgCreate undefined
--	h <- openFile "5faj3Djst23W.clt" ReadMode
--	h <- openFile "test/lTYwp81ePbUe.clt" ReadMode
--	h <- openFile "test/M0DX4xktitrR.clt" ReadMode
--	hcl <- openFile "test/cjIjoSOkYHhC.clt" ReadMode
--	hsv <- openFile "test/cjIjoSOkYHhC.srv" ReadMode
--	hcl <- openFile "test/mK4s1F91+46g.clt" ReadMode
--	hsv <- openFile "test/mK4s1F91+46g.srv" ReadMode
	names <- getNames
	forM_ (map ("test" </>) names) $ \n -> do
		css <- readIO =<< readFile (n <.> "css")
		hcl <- openFile (n <.> "clt") ReadMode
		hsv <- openFile (n <.> "srv") ReadMode
		server (TestHandle hcl hsv) g0 css rsa ec mcs

data TestHandle = TestHandle Handle Handle deriving Show

instance HandleLike TestHandle where
	type HandleMonad TestHandle = IO
	hlPut (TestHandle _ h) bs = do
--		BSC.putStrLn $ hexdump bs
		bs0 <- BS.hGet h $ BS.length bs
		unless (bs == bs0) . error $
			"\n\tEXPECTED: " ++ show bs0 ++
			"\n\tACTUAL  : " ++ show bs ++ "\n"
--		BS.appendFile "test.srv" bs
--		hlPut h bs
	hlGet (TestHandle h _) n = do
		BS.hGet h n
--		bs <- hlGet h n
--		BSC.putStrLn $ hexdump bs
--		BS.appendFile "test.clt" bs
--		return bs
	hlClose (TestHandle cl sv) = hlClose cl >> hlClose sv
	hlDebug (TestHandle cl sv) = BS.putStr

instance ValidateHandle TestHandle where
	vldt'' (TestHandle _ _) = vldt'' (undefined :: Handle)

hexdump :: BS.ByteString -> BS.ByteString
hexdump = BSC.unlines . map (BSC.pack . unwords)
	. separate 16 . map (toTwo . (`showHex` "")) . BS.unpack

toTwo :: String -> String
toTwo s = replicate (2 - length s) '0' ++ s

separate :: Int -> [a] -> [[a]]
separate _ [] = []
separate n xs = take n xs : separate n (drop n xs)

getNames :: IO [FilePath]
getNames = tail . nub . sort . map dropExtensions <$>
	getDirectoryContents "test"
