module Main (main) where

import Control.Monad
import Control.Concurrent
import System.Environment
import System.IO
import Network

import Fragment
import Content
-- import Basic

main :: IO ()
main = do
	[pcl, psv] <- getArgs
	withSocketsDo $ do
		sock <- listenOn . PortNumber . fromIntegral =<< (readIO pcl :: IO Int)
		putStrLn $ "Listening on " ++ pcl
		sockHandler sock . PortNumber . fromIntegral =<< (readIO psv :: IO Int)

sockHandler :: Socket -> PortID -> IO ()
sockHandler sock pid = do
	(cl, _, _) <- accept sock
	hSetBuffering cl NoBuffering
	sv <- connectTo "localhost" pid
	commandProcessor cl sv			-- forkIO
	sockHandler sock pid

commandProcessor :: Handle -> Handle -> IO ()
commandProcessor cl sv = do
	_ <- forkIO $ evalTlsIO clientToServer (ClientHandle cl) (ServerHandle sv)
	_ <- forkIO $ evalTlsIO serverToClient (ClientHandle cl) (ServerHandle sv)
	return ()

clientToServer :: TlsIO ()
clientToServer = do
	toChangeCipherSpec Client Server
	liftIO $ putStrLn "-------- Client Change Cipher Spec --------"
	forever $ do
		f <- readRawFragment Client
		liftIO $ print f
		writeRawFragment Server f

serverToClient :: TlsIO ()
serverToClient = do
	toChangeCipherSpec Server Client
	liftIO $ putStrLn "-------- Server Change Cipher Spec --------"
	forever $ do
		f <- readRawFragment Server
		liftIO $ print f
		writeRawFragment Client f

toChangeCipherSpec :: Partner -> Partner -> TlsIO ()
toChangeCipherSpec from to = do
	f@(Fragment ct _ _) <- readFragment from
	let	Right c = fragmentToContent f
		f' = contentToFragment c
	liftIO $ print c
	writeFragment to f'
	case ct of
		ContentTypeChangeCipherSpec -> return ()
		_ -> toChangeCipherSpec from to
