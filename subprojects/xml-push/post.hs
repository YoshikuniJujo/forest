{-# LANGUAGE PackageImports #-}

import Control.Applicative
import Control.Monad
import "monads-tf" Control.Monad.Trans
import Data.Pipe
import System.Environment
import System.IO
import Network
import Network.TigHTTP.Client
import Network.TigHTTP.Types

import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as LBS

main :: IO ()
main = do
	addr : pth : _ <- getArgs
	h <- connectTo addr $ PortNumber 80
	run h addr pth

run :: Handle -> String -> String -> IO ()
run h addr pth = words <$> getLine >>= \msgs -> if null msgs then return () else do
	let msg = LBS.fromChunks $ map BSC.pack msgs
	r <- request h $ post addr 80 pth
		(Nothing, msg)
--		(Just . fromIntegral $ LBS.length msg, msg)
	void . runPipe $ responseBody r =$= (printP `finally` putStrLn "")
	run h addr pth

printP :: MonadIO m => Pipe BSC.ByteString () m ()
printP = await >>= maybe (return ()) (\s -> liftIO (BSC.putStr s) >> printP)

readLines :: IO [String]
readLines = do
	l <- getLine
	if null l then return [] else (l :) <$> readLines
