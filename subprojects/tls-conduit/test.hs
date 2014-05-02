module Main (main) where

import Control.Monad
import Control.Concurrent
import System.Environment
import System.IO
import Network
import Numeric

import Data.List
import Data.Word
import Data.ByteString (ByteString, unpack)

import Data.X509.File
import Data.X509
import Crypto.PubKey.RSA

import Fragment
import Content
import Handshake
import PreMasterSecret
-- import Basic

main :: IO ()
main = do
	[PrivKeyRSA privateKey] <- readKeyFile "localhost.key"
	print privateKey
	[pcl, psv] <- getArgs
	withSocketsDo $ do
		sock <- listenOn . PortNumber . fromIntegral =<< (readIO pcl :: IO Int)
		putStrLn $ "Listening on " ++ pcl
		sockHandler privateKey sock . PortNumber . fromIntegral =<<
			(readIO psv :: IO Int)

sockHandler :: PrivateKey -> Socket -> PortID -> IO ()
sockHandler pk sock pid = do
	(cl, _, _) <- accept sock
	hSetBuffering cl NoBuffering
	sv <- connectTo "localhost" pid
	commandProcessor cl sv pk		-- forkIO
	sockHandler pk sock pid

commandProcessor :: Handle -> Handle -> PrivateKey -> IO ()
commandProcessor cl sv pk = do
	_ <- forkIO $ evalTlsIO clientToServer
		(ClientHandle cl) (ServerHandle sv) pk
	_ <- forkIO $ evalTlsIO serverToClient
		(ClientHandle cl) (ServerHandle sv) pk
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

showKey :: ByteString -> String
showKey = unlines . map ('\t' :) . map unwords . separateN 16 . map showH . unpack

showH :: Word8 -> String
showH w = replicate (2 - length s) '0' ++ s
	where
	s = showHex w ""

toChangeCipherSpec :: Partner -> Partner -> TlsIO ()
toChangeCipherSpec from to = do
	f@(Fragment ct _ _) <- readFragment from
	let	Right c = fragmentToContent f
		f' = contentToFragment c
	liftIO $ print c
	writeFragment to f'
	case c of
		ContentHandshake _ [HandshakeClientKeyExchange
			(EncryptedPreMasterSecret epms)] -> do
			liftIO $ putStrLn "Pre-Master Secret"
			decryptRSA epms >>= liftIO . putStrLn . showKey
		_ -> return ()
	case ct of
		ContentTypeChangeCipherSpec -> return ()
		_ -> toChangeCipherSpec from to

separateN :: Int -> [a] -> [[a]]
separateN _ [] = []
separateN n xs = take n xs : separateN n (drop n xs)
