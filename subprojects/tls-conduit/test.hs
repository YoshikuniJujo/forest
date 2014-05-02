module Main (main) where

import Control.Monad
import Control.Concurrent
import System.Environment
import System.IO
import Network
import Numeric

import Data.Maybe
-- import Data.List
import Data.Word
import Data.ByteString (ByteString, unpack)

import Data.X509.File
import Data.X509
import Crypto.PubKey.RSA

import Fragment
import Content
import Handshake
import ClientHello
import ServerHello
import PreMasterSecret
import Parts
-- import Basic

main :: IO ()
main = do
	[PrivKeyRSA privateKey] <- readKeyFile "localhost.key"
--	print privateKey
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
	_ <- forkIO $ commandProcessor cl sv pk		-- forkIO
	sockHandler pk sock pid

commandProcessor :: Handle -> Handle -> PrivateKey -> IO ()
commandProcessor cl sv pk = do
	evalTlsIO conversation (ClientHandle cl) (ServerHandle sv) pk
	_ <- forkIO $ evalTlsIO clientToServer
		(ClientHandle cl) (ServerHandle sv) pk
	evalTlsIO serverToClient
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
	msr <- serverHello Nothing
	case msr of
		Just (Random sr) -> do
			setServerRandom sr
			liftIO $ do
				putStrLn "### SERVER RANDOM ###"
				putStrLn $ showKey sr
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

clientHello :: TlsIO (Maybe Random)
clientHello = do
	f <- readFragment Client
	let	Right c = fragmentToContent f
		f' = contentToFragment c
	liftIO $ print c
	writeFragment Server f'
	return $ clientRandom c

serverHello :: Maybe Random -> TlsIO (Maybe Random)
serverHello msr = do
	f <- readFragment Server
	let	Right c = fragmentToContent f
		f' = contentToFragment c
	liftIO $ print c
	writeFragment Client f'
	if doesServerHelloFinish c
		then return $ msr `mplus` serverRandom c
		else serverHello $ msr `mplus` serverRandom c

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
		ContentHandshake _ hss -> forM_ hss $ \hs -> do
			case hs of
				HandshakeClientHello (ClientHello _ (Random r) _ _ _ _) -> do
					setClientRandom r
				HandshakeServerHello (ServerHello _ (Random r) _ _ _ _) -> do
					setServerRandom r
				HandshakeClientKeyExchange
					(EncryptedPreMasterSecret epms) -> do
					liftIO $ putStrLn "Pre-Master Secret"
					decryptRSA epms >>= liftIO . putStrLn . showKey
--					generateMasterSecret =<< decryptRSA epms
				_ -> return ()
		_ -> return ()
	case ct of
		ContentTypeChangeCipherSpec -> return ()
		_ -> toChangeCipherSpec from to

separateN :: Int -> [a] -> [[a]]
separateN _ [] = []
separateN n xs = take n xs : separateN n (drop n xs)
