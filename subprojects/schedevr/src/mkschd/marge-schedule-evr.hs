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
	let (ilfps, "--" : fps) = span (/= "--") args
	tbl <- concat <$> mapM readFile ilfps
	items <- mapM (fmap parse . readFile) fps
--	cnt1 <- readFile "test.schd"
--	cnt2 <- readFile "test2.schd"
--	putStr $ showOutputs $ fromItem2 (read "2014-04-22") (parse cnt1) (parse cnt2)
	putStrLn "start\t2014-04-17"
	putStr $ evrOutputs $ fromItemN (read "2014-04-17") items
