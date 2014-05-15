import System.Console.GetOpt
import System.Environment

main :: IO ()
main = do
	args <- getArgs
	print $ getOpt Permute options args

data Option = Hoge
	deriving Show

options :: [OptDescr Option]
options = [
	Option "h" ["hoge"] (NoArg Hoge) "hogeru"
 ]
