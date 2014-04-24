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
	"-s" : s : args <- getArgs
	let (ilfps, "--" : fps) = span (/= "--") args
	tbl <- concat <$> mapM readFile ilfps
	items <- mapM (fmap parse . readFile) fps
--	cnt1 <- readFile "test.schd"
--	cnt2 <- readFile "test2.schd"
--	putStr $ showOutputs $ fromItem2 (read "2014-04-22") (parse cnt1) (parse cnt2)
	putStr $ showOutputs $ map (convertOutput tbl) $
		fromItemN (read s) items
