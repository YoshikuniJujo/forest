{-# LANGUAGE OverloadedStrings, TypeFamilies, PackageImports #-}

module Main (main) where

import Control.Applicative((<$>))
import Control.Monad (unless, forM_)
import Data.List (sort, nub)
import Data.HandleLike (HandleLike(..))
import System.IO (Handle, IOMode(..), openFile, hClose)
import System.Directory (getDirectoryContents)
import System.FilePath (dropExtensions, (</>), (<.>))
import System.Environment (getArgs)
import "crypto-random" Crypto.Random (cprgCreate)

import qualified Data.ByteString as BS

import MyServer (server, ValidateHandle(..))
import CommandLine (readCommandLine)
import Random (StdGen)

main :: IO ()
main = do
	(_prt, _css, rsa, ec, mcs, td) <- readCommandLine =<< getArgs
	let g = cprgCreate undefined :: StdGen
	nms <- map (td </>) . tail . nub . sort .
		map dropExtensions <$> getDirectoryContents td
	forM_ nms $ \n -> do
--		print n
		css <- readIO =<< readFile (n <.> "css")
		cl <- openFile (n <.> "clt") ReadMode
		sv <- openFile (n <.> "srv") ReadMode
		server g (TestHandle cl sv) css rsa ec mcs

data TestHandle = TestHandle Handle Handle deriving Show

instance HandleLike TestHandle where
	type HandleMonad TestHandle = IO
	hlPut (TestHandle _ sv) bs = do
		bs0 <- BS.hGet sv $ BS.length bs
		unless (bs == bs0) . error $
			"\n\tEXPECTED: " ++ show bs0 ++
			"\n\tACTUAL  : " ++ show bs ++ "\n"
	hlGet (TestHandle cl _) = BS.hGet cl
	hlClose (TestHandle cl sv) = hClose cl >> hClose sv
	hlDebug _ n
		| n > 3 = BS.putStr
		| otherwise = const $ return ()

instance ValidateHandle TestHandle where
	validate (TestHandle _ _) = validate (undefined :: Handle)
