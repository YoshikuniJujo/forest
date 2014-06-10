{-# LANGUAGE OverloadedStrings, TypeFamilies, PackageImports #-}

module Main (main) where

import Control.Applicative((<$>))
import Control.Monad (unless, forM_)
import Data.List (nub, sort)
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
	(_port, _css, rsa, ec, mcs) <- readCommandLine =<< getArgs
	let g = cprgCreate undefined :: StdGen
	fps <- getPaths
	forM_ (map ("test" </>) fps) $ \n -> do
		css <- readIO =<< readFile (n <.> "css")
		cl <- openFile (n <.> "clt") ReadMode
		sv <- openFile (n <.> "srv") ReadMode
		server (TestHandle cl sv) g css rsa ec mcs

data TestHandle = TestHandle Handle Handle deriving Show

instance HandleLike TestHandle where
	type HandleMonad TestHandle = IO
	hlPut (TestHandle _ h) bs = do
		bs0 <- BS.hGet h $ BS.length bs
		unless (bs == bs0) . error $
			"\n\tEXPECTED: " ++ show bs0 ++
			"\n\tACTUAL  : " ++ show bs ++ "\n"
	hlGet (TestHandle h _) = BS.hGet h
	hlClose (TestHandle cl sv) = hClose cl >> hClose sv
	hlDebug _ n
		| n > 3 = BS.putStr
		| otherwise = const $ return ()

instance ValidateHandle TestHandle where
	validate (TestHandle _ _) = validate (undefined :: Handle)

getPaths :: IO [FilePath]
getPaths = tail . nub . sort . map dropExtensions <$> getDirectoryContents "test"
