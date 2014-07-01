import Paths_sample

main = do
	fp <- getDataFileName "name.txt"
	name <- readFile fp
	putStrLn $ "Hello, " ++ init name ++ "!"
