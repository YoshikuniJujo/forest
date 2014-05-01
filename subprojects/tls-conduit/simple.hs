module Main (main) where

import Control.Applicative
import Data.Maybe

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
import PreMasterSecret

import Data.X509.File
import Data.X509
import Crypto.PubKey.RSA
import Crypto.PubKey.RSA.PKCS15

import System.IO.Unsafe

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

peekFinished :: Handle -> Handle -> IO [Content]
peekFinished from to = do
	ec <- peek from to
	case ec of
		Right c -> case contentToHandshakeList c of
			Just hss -> do
				if (HandshakeTypeFinished `elem`
					map handshakeToHandshakeType hss)
					then return [c]
					else (c :) <$> peekFinished from to
			_ -> (c :) <$> peekFinished from to
		Left err -> putStrLn err >> return []

commandProcessor :: Handle -> Handle -> IO ()
commandProcessor cl sv = do
	hSetBuffering cl NoBuffering
	hSetBuffering sv NoBuffering
	hSetBuffering stdout NoBuffering

	putStrLn "CLIENT:"
	c1 <- peek cl sv
	putStrLn $ take 10 (show c1) ++ "...\n"
--	print c1

	putStrLn "SERVER:"
	s1 <- peekServerHelloDone sv cl
	putStrLn $ take 10 (show s1) ++ "...\n"
--	print s2

	putStrLn "CLIENT:"
	c2 <- peekFinished cl sv
	putStrLn $ take 10 (show c2) ++ "...\n"
--	print c2

	putStrLn "*** CLIENTKEYEXCHANGE ***"
	let Right preMasterSecret = decrypt Nothing private_key $ rawEncryptedPreMasterSecret $ fromJust $ takeEncryptedPreMasterSecret $ head $ fromJust $ takeHandshakes $ head c2
	print preMasterSecret
	print $ BS.length preMasterSecret
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
