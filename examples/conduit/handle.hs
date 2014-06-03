import System.IO

main :: IO ()
main = do
	hClose stdin
	hIsClosed stdin >>= print
