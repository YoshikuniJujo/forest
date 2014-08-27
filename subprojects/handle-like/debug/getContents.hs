import Data.HandleLike
import System.IO

main :: IO ()
main = do
	hlGetContent stdin >>= print
