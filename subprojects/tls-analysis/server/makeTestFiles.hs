{-# LANGUAGE TypeFamilies, PackageImports #-}

module Main (main) where

import Control.Applicative ((<$>), (<*>))
import Control.Monad (forever)
import Control.Concurrent (forkIO)
import Data.Ratio (numerator)
import Data.Time (UTCTime(..), getCurrentTime, toModifiedJulianDay)
import Data.HandleLike (HandleLike(..))
import System.IO (Handle, openFile, IOMode(..))
import System.Environment (getArgs)
import System.Directory (createDirectoryIfMissing)
import System.FilePath ((</>), (<.>))
import System.Posix.Process (getProcessID)
import Network (listenOn, accept)
import "crypto-random" Crypto.Random (CPRG(..))

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Base64 as BASE64
import qualified Crypto.Hash.SHA256 as SHA256

import TestServer (server, ValidateHandle(..))
import CommandLine (readOptions)
import TestRandom (StdGen)

main :: IO ()
main = do
	(prt, cs, rsa, ec, mcs, td) <- readOptions =<< getArgs
	createDirectoryIfMissing False td
	let g = cprgCreate undefined :: StdGen
	soc <- listenOn prt
	forever $ do
		(h, _, _) <- accept soc
		fp <- (td </>) <$> createName
		writeFile (fp <.> "cs") $ show cs ++ "\n"
		cl <- openFile (fp <.> "clt") WriteMode
		sv <- openFile (fp <.> "srv") WriteMode
		forkIO $ server g (DebugHandle h cl sv) cs rsa ec mcs

data DebugHandle = DebugHandle Handle Handle Handle deriving Show

instance ValidateHandle DebugHandle where
	validate (DebugHandle h _ _) = validate h

instance HandleLike DebugHandle where
	type HandleMonad DebugHandle = IO
	hlPut (DebugHandle h _ sv) = (>>) <$> BS.hPut sv <*> hlPut h
	hlGet (DebugHandle h cl _) n = hlGet h n >>= (>>) <$> BS.hPut cl <*> return
	hlClose (DebugHandle h cl sv) = hlClose `mapM_` [h, cl, sv]
	hlDebug (DebugHandle h _ _) = hlDebug h

createName :: IO FilePath
createName = do
	now <- getCurrentTime
	pid <- getProcessID
	return . BSC.unpack . sub '/' '-' . BS.take 12 . BASE64.encode .
		SHA256.hash . BSC.pack $ concat [
			show . toModifiedJulianDay $ utctDay now,
			show . numerator . toRational $ utctDayTime now,
			show pid ]

sub :: Char -> Char -> BS.ByteString -> BS.ByteString
sub pre pst bs
	| Just (c, bs') <- BSC.uncons bs =
		BSC.cons (if c == pre then pst else c) $ sub pre pst bs'
	| otherwise = BS.empty
