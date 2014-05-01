{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Control.Applicative
import Data.Maybe
import Data.Word

import Network
import System.IO
import System.Environment
import Control.Concurrent
import Control.Monad
import Data.Char
import Numeric
import qualified Data.ByteString as BS

import Fragment
import Content
import Handshake
import ClientHello
import ServerHello
import PreMasterSecret
import MasterSecret

import Data.X509.File
import Data.X509
import Crypto.PubKey.RSA
import Crypto.PubKey.RSA.PKCS15

import System.IO.Unsafe

import Crypto.Cipher.AES

private_key :: PrivateKey
private_key = unsafePerformIO $ do
	[PrivKeyRSA priv] <- readKeyFile "localhost.key"
	return priv

main :: IO ()
main = do
--	print =<< readKeyFile "localhost.key"
	[PrivKeyRSA priv] <- readKeyFile "localhost.key"
--	print priv
	p1 : p2 : _ <- getArgs
	withSocketsDo $ do
		sock <- listenOn $ PortNumber $ fromIntegral $ (read p1 :: Int)
		putStrLn $ "Listening on " ++ p1
		sockHandler sock (PortNumber $ fromIntegral $ (read p2 :: Int))

sockHandler :: Socket -> PortID -> IO ()
sockHandler sock pid = do
	(cl, _, _) <- accept sock
	hSetBuffering cl NoBuffering
	sv <- connectTo "localhost" pid
	commandProcessor cl sv
	sockHandler sock pid 

readContent :: Handle -> IO (Either String Content)
readContent h = do
	Fragment ct v body <- readFragment h
	return $ content ct v body

peek :: Handle -> Handle -> IO (Either String Content)
peek from to = do
	f@(Fragment ct v body) <- readFragment from
	let econt = content ct v body
	case econt of
		Right cont -> BS.hPutStr to $ contentToByteString cont
		Left err -> do
			putStrLn err
			BS.hPutStr to $ fragmentToByteString f
	return econt

peekFragment :: Handle -> Handle -> IO Fragment
peekFragment from to = do
	cont <- readFragment from
	BS.hPutStr to $ fragmentToByteString cont
	return cont

peekChar :: Handle -> Handle -> IO Char
peekChar from to = do
	c <- hGetChar from
	hPutChar to c
	return c

peekServerHelloDone :: Handle -> Handle -> IO [Content]
peekServerHelloDone sv cl = do
	Right c <- peek sv cl
	case contentToHandshakeList c of
		Just hss -> do
			let hts = map handshakeToHandshakeType hss
			if (HandshakeTypeServerHelloDone `elem` hts ||
				HandshakeTypeFinished `elem` hts)
				then return [c]
				else (c :) <$> peekServerHelloDone sv cl
		_ -> do	putStrLn "NOT HANDSHAKE"
			print c
			return [c]
--			(c :) <$> peekServerHelloDone sv cl

peekFinished :: BS.ByteString -> BS.ByteString -> Handle -> Handle -> IO [Content]
peekFinished key iv from to = do
	Fragment ct v body <- peekFragment from to
	let ec = content ct v body
	case ec of
		Right c -> case contentToHandshakeList c of
			Just hss -> do
				if (HandshakeTypeFinished `elem`
					map handshakeToHandshakeType hss)
					then return [c]
					else (c :) <$> peekFinished key iv from to
			_ -> (c :) <$> peekFinished key iv from to
		Left err -> do
			putStrLn err
			print body
			let aes = initAES key
			print $ decryptCBC aes iv body
			return []

commandProcessor :: Handle -> Handle -> IO ()
commandProcessor cl sv = do
	hSetBuffering cl NoBuffering
	hSetBuffering sv NoBuffering
	hSetBuffering stdout NoBuffering

	putStrLn "CLIENT:"
	Right c1 <- peek cl sv
	putStrLn $ take 10 (show c1) ++ "...\n"
--	print c1

	putStrLn "*** CLIENT RANDOM ***"
	let client_random = fromJust $ takeClientRandom $ fromJust $ takeClientHello $ head $ fromJust $ takeHandshakes c1
	print client_random
	putStrLn ""

	putStrLn "SERVER:"
	s1 <- peekServerHelloDone sv cl
	putStrLn $ take 10 (show s1) ++ "...\n"
--	print s1

	putStrLn "*** SERVER RANDOM ***"
	let server_random = fromJust $ takeServerRandom $ fromJust $ takeServerHello $ head $ fromJust $ takeHandshakes $ head s1
	print server_random
	putStrLn ""

	putStrLn "CLIENT AGAIN:"
	Right c2 <- peek cl sv
	print c2
	putStrLn ""

	putStrLn "*** PREMASTER SECRET ***"
	let Right pre_master_secret = decrypt Nothing private_key $ rawEncryptedPreMasterSecret $ fromJust $ takeEncryptedPreMasterSecret $ head $ fromJust $ takeHandshakes $ c2
	print pre_master_secret
	print $ BS.length pre_master_secret
	putStrLn ""

	putStrLn "*** MASTER SECRET ***"
	let master_secret = masterSecret pre_master_secret client_random server_random
	print master_secret
	putStrLn ""

	putStrLn "*** EXPANDED MASTER SECRET ***"
	let expanded = keyBlock client_random server_random master_secret 96
	print expanded
	print $ BS.length expanded
	putStrLn ""

	let [client_write_MAC_key, server_write_MAC_key,
		client_write_key, server_write_key,
		client_write_iv, server_write_iv] = divide 16 expanded
	putStrLn "*** KEY LIST ***"
	putStrLn $ "client MAC: " ++ showKey client_write_MAC_key
	putStrLn $ "server MAC: " ++ showKey server_write_MAC_key
	putStrLn $ "client key: " ++ showKey client_write_key
	putStrLn $ "server key: " ++ showKey server_write_key
	putStrLn $ "client iv : " ++ showKey client_write_iv
	putStrLn $ "server iv : " ++ showKey server_write_iv
	putStrLn ""

	putStrLn "CLIENT CRYPTED AGAIN:"
	c3 <- peekFinished client_write_key client_write_iv cl sv
--	putStrLn $ take 10 (show c2) ++ "...\n"
	print c3
	putStrLn ""

--	peekChar cl sv >>= print
--	peekChar sv cl >>= print

{-
	f@(Fragment ct v body) <- peekFragment sv cl
	print f
	print $ content ct v body
	-}

--	peek sv cl >>= print

--	putStrLn "TEST:"
--	peek sv cl >>= print

--	putStrLn "CLIENT:"
--	peek cl sv >>= print

	_ <- forkIO $ forever $ do
		c <- hGetChar cl
		putEscChar c
		hPutChar sv c
	_ <- forkIO $ forever $ do
		c <- hGetChar sv
		putEscChar c
		hPutChar cl c
	return ()

printable :: [Char]
printable = ['0' .. '9'] ++ ['a' .. 'z'] ++ ['A' .. 'Z'] ++ symbols ++ " "

symbols :: [Char]
symbols = "$+<=>^`|~!\"#%&'()*,-./:;?@[\\]_{}"

putEscChar :: Char -> IO ()
putEscChar c
	| c `elem` printable = do
		putChar c
	| otherwise = do
		putStr (toTwo (showHex (ord c) ""))

toTwo :: String -> String
toTwo n = replicate (2 - length n) '0' ++ n

divide :: Int -> BS.ByteString -> [BS.ByteString]
divide n bs
	| bs == BS.empty = []
	| otherwise = let (x, xs) = BS.splitAt n bs in x : divide n xs

showKey :: BS.ByteString -> String
showKey = unwords . map showH . BS.unpack

showH :: Word8 -> String
showH w = replicate (2 - length s) '0' ++ s
	where
	s = showHex w ""
