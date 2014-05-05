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
import Data.Word
import Data.ByteString (ByteString, unpack)

import Data.X509.File
import Data.X509
import Crypto.PubKey.RSA

import Fragment
import Content
-- import Handshake
-- import ClientHello
-- import ServerHello
import PreMasterSecret
import Parts
-- import Basic

import Data.IORef

import System.IO.Unsafe

locker :: Chan ()
locker = unsafePerformIO $ do
	c <- newChan
	writeChan c ()
	return c

lock, unlock :: IO ()
lock = readChan locker
unlock = writeChan locker ()

main :: IO ()
main = do
	cidRef <- newIORef 0
	[PrivKeyRSA privateKey] <- readKeyFile "localhost.key"
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
	_ <- forkIO $ commandProcessor cid cl sv pk
	sockHandler cidRef pk sock pid

commandProcessor :: Int -> Handle -> Handle -> PrivateKey -> IO ()
commandProcessor cid cl sv =
	evalTlsIO conversation cid (ClientHandle cl) (ServerHandle sv)
	{-
	_ <- forkIO $ evalTlsIO clientToServer cid
		(ClientHandle cl) (ServerHandle sv) pk
	evalTlsIO serverToClient cid
		(ClientHandle cl) (ServerHandle sv) pk
		-}

conversation :: TlsIO ()
conversation = do
	cid <- clientId
	liftIO $ do
		lock
		putStrLn $ "-------- Client(" ++ show cid ++ ") Say Hello ---------"
	mcr <- clientHello
	case mcr of
		Just (Random cr) -> do
			setClientRandom cr
			liftIO $ do
				putStrLn "### CLIENT RANDOM ###"
				putStr $ showKey cr
				putStrLn ""
				unlock
		_ -> return ()
	liftIO $ do
		lock
		putStrLn $ "-------- Server(" ++ show cid ++ ") Say Hello --------"
	msrcs <- serverHello Nothing Nothing
	case msrcs of
		(Just (Random sr), Just cs) -> do
			setServerRandom sr
			cacheCipherSuite cs
			liftIO $ do
				putStrLn "### SERVER RANDOM ###"
				putStr $ showKey sr
				putStrLn "### CIPHER SUITE ###"
				putStrLn $ "\t" ++ show cs
		_ -> return ()
	liftIO $ do
		putStrLn "-------- Server Hello Done --------"
		putStrLn ""
		unlock
	liftIO lock
	liftIO . putStrLn $
		"-------- Client(" ++ show cid ++ ") Key Exchange ----------"
	mepms <- clientKeyExchange
	case mepms of
		Just (EncryptedPreMasterSecret epms) -> do
			pms <- decryptRSA epms
			liftIO $ do
				putStrLn "### ENCRYPTED PRE MASTER SECRET ###"
				putStr $ showKey epms
			liftIO $ do
				putStrLn "### PRE MASTER SECRET ###"
				putStr $ showKey pms
			generateMasterSecret pms
			masterSecret >>= \(Just ms) -> liftIO $ do
				putStrLn "### MASTER SECRET ###"
				putStr $ showKey ms
			{-
			expandedMasterSecret >>= \(Just ems) -> liftIO $ do
				putStrLn "### EXPANDED MASTER SECRET ###"
				putStr $ showKey ems
			-}
			debugPrintKeys
			liftIO $ putStrLn ""
		_ -> return ()
	liftIO unlock
	liftIO $ do
		lock
		putStrLn $ "---------- Client(" ++ show cid ++
			") Change Cipher Spec --------"
	changeCipherSpec Client
	liftIO $ do
		putStrLn ""
		unlock
	finishedHash Client >>= liftIO . print
	_ <- peekContent Client
	changeCipherSpec Server
	finishedHash Server >>= liftIO . print
	_ <- peekContent Server
	when (cid == 1) $ do
		begin $ "---------- Client(" ++ show cid ++ ") ------------"
		_ <- peekContent Client
		_ <- peekContent Client
		_ <- peekContent Server
		end

begin :: String -> TlsIO ()
begin msg = liftIO $ lock >> putStrLn msg

end :: TlsIO ()
end = liftIO unlock

changeCipherSpec :: Partner -> TlsIO ()
changeCipherSpec partner = do
	c <- peekContent partner
	case c of
		ContentChangeCipherSpec _ ChangeCipherSpec ->
			flushCipherSuite partner
		_ -> throwError "Not Change Cipher Spec"

peekContent :: Partner -> TlsIO Content
peekContent partner = do
	f <- readFragment partner
	let	Right c = fragmentToContent f
		f' = contentToFragment c
	writeFragment (opponent partner) f'
	liftIO $ do
		case c of
			ContentHandshake _ hss -> mapM_ print hss
			_ -> print c
		putStrLn ""
	return c

clientHello :: TlsIO (Maybe Random)
clientHello = clientRandom <$> peekContent Client

serverHello :: Maybe Random -> Maybe CipherSuite ->
	TlsIO (Maybe Random, Maybe CipherSuite)
serverHello msr mcs = do
	f <- readFragment Server
	let	Right c@(ContentHandshake _ hs) = fragmentToContent f
		f' = contentToFragment c
	liftIO $ mapM_ (putStrLn . (++ " ...") . take 50 . show) hs
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
	liftIO . putStrLn . (++ " ...") . take 50 $ show cont
	writeFragment Server f'
	if doesClientKeyExchange cont
		then return $ encryptedPreMasterSecret cont
		else clientKeyExchange

{-
clientToServer :: TlsIO ()
clientToServer = do
	cid <- clientId
	liftIO $ do
		lock
		putStrLn $ "-------- Client(" ++ show cid ++
			") Data Application Begin --------"
		unlock
	forever $ do
		f <- readFragment Client
		liftIO $ print f
		writeFragment Server f

serverToClient :: TlsIO ()
serverToClient = do
	cid <- clientId
	liftIO $ do
		lock
		putStrLn $ "-------- Server(" ++ show cid ++
			") Data Application Begin --------"
		unlock
	forever $ do
		f <- readFragment Server
		liftIO $ print f
		writeFragment Client f
		-}

showKey :: ByteString -> String
showKey = unlines . map (('\t' :) . unwords) . separateN 16 . map showH . unpack

showH :: Word8 -> String
showH w = replicate (2 - length s) '0' ++ s
	where
	s = showHex w ""

separateN :: Int -> [a] -> [[a]]
separateN _ [] = []
separateN n xs = take n xs : separateN n (drop n xs)
