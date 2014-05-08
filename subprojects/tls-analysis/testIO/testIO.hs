import Control.Concurrent
import System.IO.Unsafe

c2s, s2c :: Chan String
c2s = unsafePerformIO newChan
s2c = unsafePerformIO newChan

type Hndl = (IO String, String -> IO ())

hOpen :: (IO String, String -> IO ()) -> IO Hndl
hOpen = return

hGet :: Hndl -> IO String
hGet (g, _) = g

hPut :: Hndl -> String -> IO ()
hPut (_, p) = p

client :: IO ()
client = do
	h <- hOpen (readChan s2c, writeChan c2s)
	hPut h "Hello"
	hGet h >>= putStrLn . ("Server Say " ++)

server :: IO ()
server = do
	h <- hOpen (readChan c2s, writeChan s2c)
	hGet h >>= putStrLn . ("Client Say " ++)
	hPut h "Hello"

conversation :: IO ()
conversation = do
	forkIO server
	client
