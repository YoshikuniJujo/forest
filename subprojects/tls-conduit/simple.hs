import Network
import System.IO
import System.Environment
import Control.Concurrent
import Control.Monad
import Data.Char
import Numeric

import ReadFragment
import qualified Data.ByteString as BS

main :: IO ()
main = do
	p1 : p2 : _ <- getArgs
	withSocketsDo $ do
		sock <- listenOn $ PortNumber $ fromIntegral $ read p1
		putStrLn $ "Listening on " ++ p1
		sockHandler sock (PortNumber $ fromIntegral $ read p2)

sockHandler :: Socket -> PortID -> IO ()
sockHandler sock pid = do
	(cl, _, _) <- accept sock
	hSetBuffering cl NoBuffering
	sv <- connectTo "localhost" pid
	commandProcessor cl sv
	sockHandler sock pid 

commandProcessor :: Handle -> Handle -> IO ()
commandProcessor cl sv = do
	hSetBuffering cl NoBuffering
	hSetBuffering sv NoBuffering
	hSetBuffering stdout NoBuffering

	f1 <- readFragment cl
	putStrLn "CLIENT:"
	print $ takeHandshake f1
	BS.hPutStr sv $ fragmentToByteString f1

	f2 <- readFragment sv
	putStrLn "SERVER:"
--	print f2
	print $ takeHandshake f2
	BS.hPutStr cl $ fragmentToByteString f2

	f3 <- readFragment sv
	putStrLn "SERVER:"
	print $ takeHandshake f3
	BS.hPutStr cl $ fragmentToByteString f3

	forkIO $ forever $ do
		c <- hGetChar cl
		putEscChar 32 c
		hPutChar sv c
	forkIO $ forever $ do
		c <- hGetChar sv
		putEscChar 31 c
		hPutChar cl c
	return ()

printable :: [Char]
printable = ['0' .. '9'] ++ ['a' .. 'z'] ++ ['A' .. 'Z'] ++ symbols ++ " "

symbols :: [Char]
symbols = "$+<=>^`|~!\"#%&'()*,-./:;?@[\\]_{}"

putEscChar :: Int -> Char -> IO ()
putEscChar clr c
	| c `elem` printable = do
		putChar c
	| otherwise = do
		putStr (toTwo (showHex (ord c) ""))

toTwo :: String -> String
toTwo n = replicate (2 - length n) '0' ++ n
