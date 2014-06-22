{-# LANGUAGE OverloadedStrings, TypeFamilies, PackageImports #-}

module Main (main) where

import Control.Applicative((<$>))
import Control.Monad (unless, forM_)
import Data.List (sort, nub)
import Data.HandleLike (HandleLike(..))
import System.IO (Handle, IOMode(..), openFile, hClose)
import System.Environment (getArgs)
import System.Directory (getDirectoryContents)
import System.FilePath ((</>), (<.>), dropExtensions)
import "crypto-random" Crypto.Random (cprgCreate)

import qualified Data.ByteString as BS

import MyServer (server, ValidateHandle(..))
import CommandLine (readOptions)
import TestRandom (StdGen)

main :: IO ()
main = do
	(_prt, _cs, rsa, ec, mcs, td) <- readOptions =<< getArgs
	let g = cprgCreate undefined :: StdGen
	nms <- map (td </>) . tail . nub . sort . map dropExtensions
		<$> getDirectoryContents td
	forM_ nms $ \n -> do
--		print n
		cs <- readIO =<< readFile (n <.> "cs")
		cl <- openFile (n <.> "clt") ReadMode
		sv <- openFile (n <.> "srv") ReadMode
		server g (TestHandle cl sv) cs rsa ec mcs

data TestHandle = TestHandle Handle Handle deriving Show

instance ValidateHandle TestHandle where
	validate (TestHandle _ _) = validate (undefined :: Handle)

instance HandleLike TestHandle where
	type HandleMonad TestHandle = IO
	hlPut (TestHandle _ sv) bs = do
		bs0 <- BS.hGet sv $ BS.length bs
		unless (bs == bs0) . error $
			"\n\tEXPECTED: " ++ show bs0 ++
			"\n\tACTUAL  : " ++ show bs ++ "\n"
	hlGet (TestHandle cl _) = BS.hGet cl
	hlClose (TestHandle cl sv) = hClose `mapM_` [cl, sv]
	hlDebug _ n | n > 3 = BS.putStr | otherwise = const $ return ()
