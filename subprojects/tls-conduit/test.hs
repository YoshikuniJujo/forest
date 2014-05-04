{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Control.Applicative
import Control.Monad
import Control.Concurrent
import System.Environment
import System.IO
import Network
import Numeric

-- import Data.Maybe
-- import Data.List
import Data.Bits
import Data.Word
import Data.ByteString (ByteString, unpack)
import qualified Data.ByteString as BS

import Data.X509.File
import Data.X509
import Crypto.PubKey.RSA
import MAC
import qualified Crypto.Hash.SHA1 as SHA1

import Fragment
import Content
-- import Handshake
-- import ClientHello
-- import ServerHello
import PreMasterSecret
import Parts
-- import Basic

import Data.IORef

import ToByteString

main :: IO ()
main = do
	cidRef <- newIORef 0
	[PrivKeyRSA privateKey] <- readKeyFile "localhost.key"
--	print privateKey
	[pcl, psv] <- getArgs
	withSocketsDo $ do
		sock <- listenOn . PortNumber . fromIntegral =<< (readIO pcl :: IO Int)
		putStrLn $ "Listening on " ++ pcl
		sockHandler cidRef privateKey sock . PortNumber . fromIntegral =<<
			(readIO psv :: IO Int)

sockHandler :: IORef Int -> PrivateKey -> Socket -> PortID -> IO ()
sockHandler cidRef pk sock pid = do
	cid <- readIORef cidRef
	modifyIORef cidRef succ
	(cl, _, _) <- accept sock
	hSetBuffering cl NoBuffering
	sv <- connectTo "localhost" pid
	_ <- forkIO $ commandProcessor cid cl sv pk		-- forkIO
	sockHandler cidRef pk sock pid

commandProcessor :: Int -> Handle -> Handle -> PrivateKey -> IO ()
commandProcessor cid cl sv pk = do
	evalTlsIO conversation cid (ClientHandle cl) (ServerHandle sv) pk
	_ <- forkIO $ evalTlsIO clientToServer cid
		(ClientHandle cl) (ServerHandle sv) pk
	evalTlsIO serverToClient cid
		(ClientHandle cl) (ServerHandle sv) pk

conversation :: TlsIO ()
conversation = do
	liftIO $ putStrLn "-------- Client Say Hello ---------"
	mcr <- clientHello
	case mcr of
		Just (Random cr) -> do
			setClientRandom cr
			liftIO $ do
				putStrLn "### CLIENT RANDOM ###"
				putStrLn $ showKey cr
		_ -> return ()
	liftIO $ putStrLn "-------- Server Say Hello --------"
	msrcs <- serverHello Nothing Nothing
	case msrcs of
		(Just (Random sr), Just cs) -> do
			setServerRandom sr
			cacheCipherSuite cs
			liftIO $ do
				putStrLn "### SERVER RANDOM ###"
				putStrLn $ showKey sr
				putStrLn "### CIPHER SUITE ###"
				print cs
		_ -> return ()
	liftIO $ putStrLn "-------- Server Hello Done --------"
	liftIO $ putStrLn "-------- Client Key Exchange ----------"
	mepms <- clientKeyExchange
	case mepms of
		Just (EncryptedPreMasterSecret epms) -> do
			liftIO $ do
				putStrLn "### ENCRYPTED PRE MASTER SECRET ###"
				putStrLn $ showKey epms
			pms <- decryptRSA epms
			liftIO $ do
				putStrLn "### PRE MASTER SECRET ###"
				putStrLn $ showKey pms
			generateMasterSecret pms
			masterSecret >>= \(Just ms) -> liftIO $ do
				putStrLn "### MASTER SECRET ###"
				putStrLn $ showKey ms
			expandedMasterSecret >>= \(Just ems) -> liftIO $ do
				putStrLn "### EXPANDED MASTER SECRET ###"
				putStrLn $ showKey ems
			debugPrintKeys
		_ -> return ()
	fh0 <- finishedHash
	changeCipherSpec Client Server
	cid <- clientId
	liftIO $ putStrLn $ ("CLIENT ID: " ++) $ show cid
--	when (cid == 0) $ readRawFragment Server >>= liftIO . print
	when (cid == 0) $ do
		liftIO $ putStrLn "----------- CLIENT FINISHED --------"
		Right c <- fragmentToContent <$> readFragment Client
		liftIO $ print c
		fh <- finishedHash
		liftIO $ putStrLn $ "FINISHED: " ++ show fh0
		liftIO $ putStrLn $ "FINISHED: " ++ show fh

	{-
		f@(RawFragment ct v body) <- readRawFragment Client
		liftIO $ do
			putStrLn "---------- CLIENT FINISHED ----------"
			print f
		decrypted <- clientWriteDecrypt body
		liftIO $ print decrypted
		let body = BS.take 16 decrypted
		liftIO $ print body
		let hash_input = "\0\0\0\0\0\0\0\0\x16\x03\x01\x00\x10" `BS.append` body
		liftIO $ print hash_input
		Just mac_key <- clientWriteMacKey
		liftIO $ putStrLn $ "HASH: " ++ show (hmac SHA1.hash 64 mac_key hash_input)
		fh <- finishedHash
		liftIO $ putStrLn $ "FINISHED: " ++ show fh0
		liftIO $ putStrLn $ "FINISHED: " ++ show fh
		let (bodyMac, padd) = separatePadd decrypted
		liftIO $ do
			print $ BS.splitAt (BS.length bodyMac - 20) bodyMac
			print padd
			-}
--	f@(RawFragment ct v body) <- readRawFragment Server -- Client
--	f@(RawFragment ct v body) <- readRawFragment Client
--	liftIO $ print f
	{-
	liftIO $ do
		print ct
		print v
	liftIO . print =<< clientWriteDecrypt body
	-}

{-
separatePadd :: ByteString -> (ByteString, ByteString)
separatePadd bs = BS.splitAt (BS.length bs - fromIntegral (BS.last bs) - 1) bs
-}

clientHello :: TlsIO (Maybe Random)
clientHello = do
	f <- readFragment Client
	let	Right c = fragmentToContent f
		f' = contentToFragment c
	liftIO $ print c
	writeFragment Server f'
	return $ clientRandom c

serverHello :: Maybe Random -> Maybe CipherSuite ->
	TlsIO (Maybe Random, Maybe CipherSuite)
serverHello msr mcs = do
	f <- readFragment Server
	let	Right c = fragmentToContent f
		f' = contentToFragment c
	liftIO $ print c
	writeFragment Client f'
	if doesServerHelloFinish c
		then return (msr `mplus` serverRandom c, mcs `mplus` cipherSuite c)
		else serverHello (msr `mplus` serverRandom c) (mcs `mplus` cipherSuite c)

clientKeyExchange :: TlsIO (Maybe EncryptedPreMasterSecret)
clientKeyExchange = do
	f <- readFragment Client
	let	cont = case fragmentToContent f of
			Right c -> c
			Left err -> error err
		f' = contentToFragment cont
	liftIO $ print cont
	writeFragment Server f'
	if doesClientKeyExchange cont
		then return $ encryptedPreMasterSecret cont
		else clientKeyExchange

clientToServer :: TlsIO ()
clientToServer = do
	liftIO $ putStrLn "-------- Client Change Cipher Spec --------"
	forever $ do
		f <- readRawFragment Client
		liftIO $ print f
		writeRawFragment Server f

serverToClient :: TlsIO ()
serverToClient = do
	liftIO $ putStrLn "-------- Server Change Cipher Spec --------"
	forever $ do
		f <- readRawFragment Server
		liftIO $ print f
		writeRawFragment Client f

showKey :: ByteString -> String
showKey = unlines . map (('\t' :) . unwords) . separateN 16 . map showH . unpack

showH :: Word8 -> String
showH w = replicate (2 - length s) '0' ++ s
	where
	s = showHex w ""

changeCipherSpec :: Partner -> Partner -> TlsIO ()
changeCipherSpec from to = do
	f <- readFragment from
	let	Right c = fragmentToContent f
		f' = contentToFragment c
	liftIO $ print c
	writeFragment to f'
	case c of
		ContentChangeCipherSpec _ ChangeCipherSpec -> flushCipherSuite from
		_ -> throwError "Not Change Cipher Spec"

separateN :: Int -> [a] -> [[a]]
separateN _ [] = []
separateN n xs = take n xs : separateN n (drop n xs)