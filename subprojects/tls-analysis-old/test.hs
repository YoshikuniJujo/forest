{-# LANGUAGE OverloadedStrings, ScopedTypeVariables, PackageImports #-}

module Main (main) where

import Control.Applicative
import Control.Arrow
import Control.Monad
import Control.Concurrent
import System.Environment
import System.IO.Unsafe
import Data.IORef
import Data.X509
import Data.X509.File
import Network

import Fragment
import Content
import PreMasterSecret
import Parts
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
		ep <- createEntropyPool
		forkIO . (\act -> evalTlsIO act ep cid client server pk) $ do
			begin Client cid "Say Hello"
			mcr <- clientRandom <$> peekContent Client
			flip (maybe $ return ()) mcr $ \cr -> do
				setClientRandom cr
				liftIO $ do
					putStrLn "### CLIENT RANDOM ###"
					putStr $ showRandom cr
			end
			begin Server cid "Say Hello"
			msrcs <- serverHello
			flip (maybe $ return ()) msrcs $ \(sr, cs) -> do
				setServerRandom sr
				cacheCipherSuite cs
				liftIO $ do
					putStrLn "### SERVER RANDOM ###"
					putStr $ showRandom sr
					putStrLn "### CIPHER SUITE ###"
					putStrLn $ "\t" ++ show cs
			end
			begin Client cid "Key Exchange"
			mepms <- encryptedPreMasterSecret <$> peekContent Client
			flip (maybe $ return ()) mepms $ \epms_ -> do
				let epms = getEncryptedPreMasterSecret epms_
				pms <- decryptRSA epms
				generateMasterSecret pms
				liftIO $ do
					putStrLn "### ENCRYPTED PRE MASTER SECRET ###"
					putStr $ showKey epms
					putStrLn "### PRE MASTER SECRET ###"
					putStr $ showKey pms
				masterSecret >>= \(Just ms) -> liftIO $ do
					putStrLn "### MASTER SECRET ###"
					putStr $ showKey ms
				debugPrintKeys
			end
			begin Client cid "Change Cipher Spec and Finished"
			cccs <- peekContent Client
			if doesChangeCipherSpec cccs
				then flushCipherSuite Client
				else throwError "Not Change Cipher Spec"
			finishedHash Client >>= liftIO . print
			_ <- peekContent Client
			end
			begin Server cid "Change Cipher Spec and Finished"
			sccs <- peekContent Server
			if doesChangeCipherSpec sccs
				then flushCipherSuite Server
				else throwError "Not Change Cipher Spec"
			finishedHash Server >>= liftIO . print
			_ <- peekContent Server
			end
			when (cid == 1) $ do
				begin Client cid ""
				_ <- peekContent Client
				_ <- peekContent Client
				end
				begin Server cid ""
				_ <- peekContent Server
				end

peekContent :: Partner -> TlsIO Content
peekContent partner = do
	Right c <- fragmentToContent <$> readFragment partner
	writeFragment (opponent partner) $ contentToFragment c
	liftIO $ case c of
		ContentHandshake _ hss ->
			forM_ hss $ putStrLn . (++ " ...") . take 50 . show
		_ -> print c
	return c

serverHello :: TlsIO (Maybe (Random, CipherSuite))
serverHello = (\(s, c) -> (,) <$> s <*> c) <$> sh (Nothing, Nothing)
	where
	sh msrcs = do
		c <- peekContent Server
		(if doesServerHelloFinish c then return else sh) .
			((`mplus` serverRandom c) *** (`mplus` cipherSuite c)) $
				msrcs
