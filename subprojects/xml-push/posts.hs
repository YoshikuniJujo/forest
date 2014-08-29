{-# LANGUAGE OverloadedStrings, TupleSections, FlexibleContexts,
	PackageImports #-}

import Control.Applicative
import Control.Monad
import "monads-tf" Control.Monad.Trans
import Data.HandleLike
import Data.Pipe
import System.Environment
import Network
import Network.PeyoTLS.Client
import Network.PeyoTLS.ReadFile
import Network.TigHTTP.Client
import Network.TigHTTP.Types
import "crypto-random" Crypto.Random

import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as LBS

main :: IO ()
main = do
	addr : pth : msgs <- getArgs
	ca <- readCertificateStore ["cacert.sample_pem"]
	h <- connectTo addr $ PortNumber 443
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	void . (`run` g) $ do
		t <- open h ["TLS_RSA_WITH_AES_128_CBC_SHA"] [] ca
		loop t addr pth

loop :: (HandleLike h, MonadIO (HandleMonad h)) => h ->
	String -> FilePath -> HandleMonad h ()
loop t addr pth = do
	msgs <- BSC.words `liftM` liftIO BSC.getLine
	r <- request t . post addr 443 pth . (Nothing ,) $  LBS.fromChunks msgs
	runPipe_ $ responseBody r =$= printP
	loop t addr pth

printP :: MonadIO m => Pipe BSC.ByteString () m ()
printP = await >>= maybe (return ()) (\s -> liftIO (BSC.putStr s) >> printP)
