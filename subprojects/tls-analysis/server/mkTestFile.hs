{-# LANGUAGE OverloadedStrings, TypeFamilies, PackageImports #-}

module Main (main) where

import Control.Applicative ((<$>))
import Control.Monad (forever, void)
import "monads-tf" Control.Monad.State (liftIO)
import Control.Concurrent (forkIO)
import Data.Ratio (numerator)
import Data.HandleLike (HandleLike(..))
import Data.Time (UTCTime(..), getCurrentTime, toModifiedJulianDay)
import System.IO (Handle, IOMode(..), BufferMode(..), openFile, hSetBuffering)
import System.Environment (getArgs)
import System.FilePath ((</>), (<.>))
import System.Directory (createDirectoryIfMissing)
import System.Posix.Process (getProcessID)
import Network (listenOn, accept)
import "crypto-random" Crypto.Random (CPRG(..))

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Base64 as BASE64
import qualified Crypto.Hash.SHA256 as SHA256

import MyServer (server, ValidateHandle(..))
import CommandLine (readCommandLine)
import Random (StdGen)

main :: IO ()
main = do
	(prt, css, td, rsa, ec, mcs) <- readCommandLine =<< getArgs
	soc <- listenOn prt
	let g = cprgCreate undefined :: StdGen
	createDirectoryIfMissing False td
	void . forever $ do
		(h, _, _) <- liftIO $ accept soc
		hSetBuffering h NoBuffering
		fp <- liftIO $ (td </>) <$> createName
		writeFile (fp <.> "css") $ show css ++ "\n"
		cl <- openFile (fp <.> "clt") WriteMode
		sv <- openFile (fp <.> "srv") WriteMode
		liftIO . forkIO $ server (DebugHandle h cl sv) g css rsa ec mcs

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

createName :: IO FilePath
createName = do
	now <- getCurrentTime
	pid <- getProcessID
	let strs = concat [
		show . toModifiedJulianDay $ utctDay now,
		show . numerator . toRational $ utctDayTime now,
		show pid ]
	return . BSC.unpack . sub '/' '-' . BS.take 12 .
		BASE64.encode . SHA256.hash $ BSC.pack strs

sub :: Char -> Char -> BS.ByteString -> BS.ByteString
sub pre pst bs
	| Just (c, bs') <- BSC.uncons bs = if c == pre
		then BSC.cons pst (sub pre pst bs')
		else BSC.cons c (sub pre pst bs')
	| otherwise = BS.empty
