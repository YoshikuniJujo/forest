import Network
import System.IO
import System.Environment
import Control.Concurrent
import Control.Monad
import Data.Char
import Numeric

main :: IO ()
main = do
	p1 : p2 : _ <- getArgs
	withSocketsDo $ do
		sock <- listenOn . PortNumber . fromIntegral $ read p1
		putStrLn $ "Listening on " ++ p1
		lock <- newChan
		writeChan lock ()
		sockHandler lock sock (PortNumber . fromIntegral $ read p2)

sockHandler :: Chan () -> Socket -> PortID -> IO ()
sockHandler lock sock pid = do
	(cl, _, _) <- accept sock
	hSetBuffering cl NoBuffering
	sv <- connectTo "localhost" pid
	forkIO $ commandProcessor lock cl sv
	sockHandler lock sock pid 

commandProcessor :: Chan () -> Handle -> Handle -> IO ()
commandProcessor lock cl sv = do
	hSetBuffering cl NoBuffering
	hSetBuffering sv NoBuffering
	hSetBuffering stdout NoBuffering
	forkIO . forever $ do
		c <- hGetChar cl
		readChan lock
		putEscChar 32 c
		writeChan lock ()
		hPutChar sv c
	forkIO . forever $ do
		c <- hGetChar sv
		readChan lock
		putEscChar 31 c
		writeChan lock ()
		hPutChar cl c
	return ()

printable :: String
printable = ['0' .. '9'] ++ ['a' .. 'z'] ++ ['A' .. 'Z'] ++ symbols ++ " "

symbols :: String
symbols = "$+<=>^`|~!\"#%&'()*,-./:;?@[\\]_{}"

putEscChar :: Int -> Char -> IO ()
putEscChar clr c
	| c `elem` printable = do
		putStr ("\x1b[1m\x1b[" ++ show clr ++ "m")
		putChar c
		putStr "\x1b[39m\x1b[0m"
	| otherwise = do
		putStr ("\x1b[" ++ show clr ++ "m")
		putStr (toTwo (showHex (ord c) ""))
		putStr "\x1b[39m"

toTwo :: String -> String
toTwo n = replicate (2 - length n) '0' ++ n
