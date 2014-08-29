{-# LANGUAGE PackageImports #-}

import Control.Monad
import "monads-tf" Control.Monad.Trans
import Control.Concurrent
import Data.Char
import Data.Pipe
import Data.Pipe.ByteString
import System.IO
import Network
import Network.TigHTTP.Server
import Network.TigHTTP.Types

import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as LBS

main :: IO ()
main = do
	soc <- listenOn $ PortNumber 80
	forever $ do
		(h, _, _) <- accept soc
		void . forkIO . forever $ run h

run :: Handle -> IO ()
run h = do
	r <- getRequest h
	print $ requestPath r
	bd <- toLazy $ requestBody r =$= convert capitalize
	putResponse h $ (response :: LBS.ByteString -> Response Pipe Handle) bd

capitalize :: BSC.ByteString -> BSC.ByteString
capitalize w = case BSC.uncons w of
	Just (h, t) -> toUpper h `BSC.cons` BSC.map toLower t
	Nothing -> w

printP :: MonadIO m => Pipe BSC.ByteString () m ()
printP = await >>= maybe (return ()) (\s -> liftIO (BSC.putStr s) >> printP)
