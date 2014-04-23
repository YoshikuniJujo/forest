module Main where

import Output
import Parser
import FromID
import System.Environment
import Control.Applicative
import Data.Time

main :: IO ()
main = do
	d <- localDay . zonedTimeToLocalTime <$> getZonedTime
	args <- getArgs
	let (_, "--" : fps) = span (/= "--") args
	items <- mapM (fmap parse . readFile) fps
	putStrLn "start\t2014-04-17"
	putStr $ evrOutputs $ fromItemN (read "2014-04-17") items
