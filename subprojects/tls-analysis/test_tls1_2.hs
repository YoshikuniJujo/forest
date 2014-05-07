{-# LANGUAGE PackageImports #-}

module Main (main) where

import Control.Applicative
import Control.Monad
import Control.Concurrent
import System.Environment
import System.IO.Unsafe
import Data.IORef
import Data.X509.File
import Data.X509

import Network

import Fragment
import Content
import PreMasterSecret
import Tools

import "crypto-random" Crypto.Random

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
		forkIO $ do
			ep <- createEntropyPool
			(\act -> evalTlsIO act ep cid client server pk) $ do
				begin Client cid "Hello"
				c1 <- peekContent Client (Just 70)
				let	Just cv = clientVersion c1
					Just cr = clientRandom c1
				setClientRandom cr
				liftIO $ do
					putStrLn . ("\t" ++) $ show cv
					putStr $ showRandom cr
				end

				begin Server cid "Hello"
				c2 <- peekContent Server (Just 70)
				c3 <- peekContent Server Nothing
				let	Just sv = serverVersion c2
					Just cs = cipherSuite c2
					Just sr = serverRandom c2
				setVersion sv
				cacheCipherSuite cs
				setServerRandom sr
				liftIO $ do
					putStrLn . ("\t" ++) $ show sv
					putStrLn . ("\t" ++) $ show cs
					putStr $ showRandom sr
				end
				return ()

				begin Client cid "Key Exchange"
				Just (EncryptedPreMasterSecret epms) <-
					encryptedPreMasterSecret <$>
						peekContent Client Nothing
				pms <- decryptRSA epms
				generateMasterSecret pms
				liftIO $ do
					print epms
					print pms
				debugPrintKeys
				end

				begin Client cid "Change Cipher Suite"
				cccs <- peekContent Client Nothing
				when (doesChangeCipherSpec cccs) $
					flushCipherSuite Client
				end

				begin Client cid "Finished"
				finishedHash Client >>= liftIO . print
				_ <- peekContent Client Nothing
				{-
				RawFragment _ e <- peekRawFragment Client
				d <- decrypt e
				-}
				end

				begin Server cid "Change Cipher Suite"
				sccs <- peekContent Server Nothing
				when (doesChangeCipherSpec sccs) $
					flushCipherSuite Server
				end

				begin Server cid "Finished"
				finishedHash Server >>= liftIO . print
				_ <- peekContent Server Nothing
				end

				when (cid == 1) $ do
					begin Client cid "GET"
					_ <- peekContent Client Nothing
					end
					begin Server cid "Contents"
					_ <- peekContent Server Nothing
					end

{-
			forkIO $ do
				ep <- createEntropyPool
				(\act -> evalTlsIO act ep cid client server pk) $ do
					forever $ do
						f <- readRawFragment Client
						writeRawFragment Server f
						begin Client cid "Others"
						liftIO $ print f
						end
			forkIO $ do
				ep <- createEntropyPool
				(\act -> evalTlsIO act ep cid client server pk) $ do
					forever $ do
						f <- readRawFragment Server
						writeRawFragment Client f
						begin Server cid "Others"
						liftIO $ print f
						end
						-}
			return ()
		return ()

peekContent :: Partner -> Maybe Int -> TlsIO Content
peekContent partner n = do
	Right c <- fragmentToContent <$> readFragment partner
	writeFragment (opponent partner) $ contentToFragment c
	liftIO . putStrLn . maybe id (((++ " ...") .) . take) n $ show c
	return c

peekRawFragment :: Partner -> TlsIO () -- RawFragment
peekRawFragment partner = do
	f <- readRawFragment partner
	writeRawFragment (opponent partner) f
	liftIO $ print f
