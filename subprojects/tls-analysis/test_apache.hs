{-# LANGUAGE PackageImports #-}

module Main (main) where

import Control.Applicative
import Control.Monad
import Control.Concurrent
import System.Environment
import System.IO.Unsafe
import Data.IORef
import Data.X509
import Data.X509.File
import "crypto-random" Crypto.Random
import Network

import Fragment
import Content
import TlsIO
import Tools

locker :: Chan ()
locker = unsafePerformIO $ ((>>) <$> (`writeChan` ()) <*> return) =<< newChan

begin :: Partner -> Int -> String -> TlsIO ()
begin partner cid msg = liftIO $ do
	readChan locker
	putStrLn $ replicate 10 '-' ++ " " ++ show partner ++ "(" ++
		show cid ++ ") " ++ msg ++ " " ++ replicate 10 '-'

end :: TlsIO ()
end = liftIO $ putStrLn "" >> writeChan locker ()

main :: IO ()
main = do
	cidRef <- newIORef 0
	[PrivKeyRSA pk] <- readKeyFile "localhost.key"
	[pcl, psv] <- mapM ((PortNumber . fromInt <$>) . readIO) =<< getArgs
	scl <- listenOn pcl
	forever $ do
		cid <- readIORef cidRef
		modifyIORef cidRef succ
		client <- ClientHandle . fst3 <$> accept scl
		server <- ServerHandle <$> connectTo "localhost" psv
		ep <- createEntropyPool
		(\act -> evalTlsIO act ep cid client server pk) $ do
			begin Client cid "Say Hello"
--			ch <- peekContentFilter Client (Just 70) onlyKnownCipherSuite
--			ch <- peekContentFilter Client Nothing onlyKnownCipherSuite
			ch <- peekContentFilter Client (Just 70) id
			let	Just cv = clientVersion ch
				Just cr = clientRandom ch
			setClientRandom cr
			liftIO $ do
				putStrLn . ("\t" ++) $ show cv
				putStr $ showRandom cr
			end

			begin Server cid "Say Hello"
			sh <- peekContent Server Nothing
			shd <- peekContent Server Nothing
			let	Just sv = serverVersion sh
				Just cs = cipherSuite sh
				Just sr = serverRandom sh
			setVersion sv
			cacheCipherSuite cs
			setServerRandom sr
			liftIO $ do
				putStrLn . ("\t" ++) $ show sv
				putStrLn . ("\t" ++) $ show cs
				putStrLn $ showRandom sr
			end

{-
			begin Client cid "Key Exchange"
			peekContent Client Nothing
			end
			-}

		_ <- forkIO $ do
			ep <- createEntropyPool
			forkIO $ do
				(\act -> evalTlsIO act ep cid client server pk) $ do
					forever $ do
						f <- readRawFragment Client
						writeRawFragment Server f
						begin Client cid "Others"
						liftIO $ print f
						end
			forkIO $ do
				(\act -> evalTlsIO act ep cid client server pk) $ do
					forever $ do
						f <- readRawFragment Server
						writeRawFragment Client f
						begin Server cid "Others"
						liftIO $ print f
						end
			return ()
		return ()

peekContentFilter :: Partner -> Maybe Int -> (Content -> Content) -> TlsIO Content
peekContentFilter partner n f = do
	ec <- (f <$>) . fragmentToContent <$> readFragment partner
	case ec of
		Right c -> do
			writeFragment (opponent partner) $ contentToFragment c
			liftIO . putStrLn .
				maybe id (((++ " ...") .) . take) n $ show c
			return c
		Left err -> throwError err

peekContent :: Partner -> Maybe Int -> TlsIO Content
peekContent partner n = do
	ec <- fragmentToContent <$> readFragment partner
	case ec of
		Right c -> do
			writeFragment (opponent partner) $ contentToFragment c
			liftIO . putStrLn .
				maybe id (((++ " ...") .) . take) n $ show c
			return c
		Left err -> throwError err
