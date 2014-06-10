{-# LANGUAGE OverloadedStrings, PackageImports, ScopedTypeVariables,
 	TypeFamilies #-}

module Main (main) where

import Control.Monad (unless, forM_)
import System.Environment (getArgs)
import "crypto-random" Crypto.Random (cprgCreate)
import MyServer (server, ValidateHandle(..))
import CommandLine (readCommandLine)

import Data.HandleLike
import qualified Data.ByteString as BS
import System.IO

import System.Directory

import Random

import System.FilePath
import Control.Applicative
import Data.List

main :: IO ()
main = do
	(_port, _css, rsa, ec, mcs) <- readCommandLine =<< getArgs
	let g0 :: StdGen = cprgCreate undefined
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
		bs0 <- BS.hGet h $ BS.length bs
		unless (bs == bs0) . error $
			"\n\tEXPECTED: " ++ show bs0 ++
			"\n\tACTUAL  : " ++ show bs ++ "\n"
	hlGet (TestHandle h _) = BS.hGet h
	hlClose (TestHandle cl sv) = hlClose cl >> hlClose sv
	hlDebug _ n
		| n > 3 = BS.putStr
		| otherwise = const $ return ()

instance ValidateHandle TestHandle where
	vldt'' (TestHandle _ _) = vldt'' (undefined :: Handle)

getNames :: IO [FilePath]
getNames = tail . nub . sort . map dropExtensions <$>
	getDirectoryContents "test"
