{-# LANGUAGE OverloadedStrings, PackageImports, ScopedTypeVariables,
 	TypeFamilies #-}

module Main (main) where

import Control.Monad (forever, void)
import "monads-tf" Control.Monad.State (liftIO)
import Control.Concurrent (forkIO)
import System.Environment (getArgs)
import Network (listenOn, accept)
import "crypto-random" Crypto.Random (CPRG(..))
import MyServer (server, ValidateHandle(..))
import CommandLine (readCommandLine)

import Data.HandleLike
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import System.IO

import System.FilePath

import Data.Time
import qualified Data.ByteString.Base64 as BASE64
import System.Posix.Process
import Data.Ratio
import Crypto.Hash.SHA256 as SHA256

import Random

import System.Directory

main :: IO ()
main = do
	(port, css, tstd, rsa, ec, mcs) <- readCommandLine =<< getArgs
	soc <- listenOn port
	let g0 :: StdGen = cprgCreate undefined
	createDirectoryIfMissing False tstd
	void . forever $ do
		(h, _, _) <- liftIO $ accept soc
		hSetBuffering h NoBuffering
		fp <- liftIO $ getName tstd
		print fp
		writeFile (fp <.> "css") $ show css ++ "\n"
		cl <- openFile (fp <.> "clt") WriteMode
		sv <- openFile (fp <.> "srv") WriteMode
		liftIO . forkIO $ server (DebugHandle h cl sv) g0 css rsa ec mcs

data DebugHandle = DebugHandle Handle Handle Handle deriving Show

instance HandleLike DebugHandle where
	type HandleMonad DebugHandle = IO
	hlPut (DebugHandle h _ sv) bs = do
		BS.hPut sv bs
		hlPut h bs
	hlGet (DebugHandle h cl _) n = do
		bs <- hlGet h n
		BS.hPut cl bs
		return bs
	hlClose (DebugHandle h cl sv) = hlClose h >> hlClose cl >> hlClose sv
	hlDebug (DebugHandle h _ _) = hlDebug h

instance ValidateHandle DebugHandle where
	validate (DebugHandle h _ _) = validate h

getName :: FilePath -> IO FilePath
getName tstd = do
	now <- getCurrentTime
	pid <- getProcessID
	let	day = utctDay now
		time = utctDayTime now
		strs = [
			show $ toModifiedJulianDay day,
			show . numerator $ toRational time,
			show pid ]
	return . (tstd </>) . BSC.unpack . sub '/' '-' . BS.take 12 .
		BASE64.encode .  SHA256.hash . BS.concat $ map BSC.pack strs

sub :: Char -> Char -> BS.ByteString -> BS.ByteString
sub pre post bs
	| Just (c, bs') <- BSC.uncons bs = if c == pre
		then BSC.cons post (sub pre post bs')
		else BSC.cons c (sub pre post bs')
	| otherwise = BS.empty
