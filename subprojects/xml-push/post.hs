{-# LANGUAGE PackageImports #-}

import Control.Applicative
import Control.Monad
import "monads-tf" Control.Monad.Trans
import Data.Maybe
import Data.HandleLike
import Data.Pipe
import Data.Pipe.List
import Data.Pipe.ByteString
import System.Environment
import System.IO
import Text.XML.Pipe
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
run h addr pth = do
	msg <- BSC.pack <$> getLine
	Just ns <- runPipe $ yield msg
		=$= xmlEvent
		=$= convert fromJust
		=$= xmlNode []
		=$= toList
	if BSC.null msg then return () else do
		runPipe_ $ fromList ns
			=$= talk h addr pth
			=$= (printP `finally` putStrLn "")
		run h addr pth

talk :: Handle -> String -> FilePath -> Pipe XmlNode XmlNode IO ()
talk h addr pth = (await >>=) . (maybe (return ())) $ \n -> do
	let m = LBS.fromChunks [xmlString [n]]
	r <- lift . request h $ post addr 80 pth (Nothing, m)
	void $ return ()
		=$= responseBody r
		=$= xmlEvent
		=$= convert fromJust
		=$= xmlNode []
	return ()

printP :: (MonadIO m, Show a) => Pipe a o m ()
printP = await >>= maybe (return ())
	(\s -> liftIO (BSC.putStr . BSC.pack $ show s) >> printP)

readLines :: IO [String]
readLines = do
	l <- getLine
	if null l then return [] else (l :) <$> readLines
