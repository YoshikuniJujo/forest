module ScheduleEVR (dayItem, dayItemFile) where

import Output
import Parser
import FromID
import Data.Time
import Control.Applicative

dayItemFile :: Day -> [FilePath] -> IO [(Day, String)]
dayItemFile b = (dayItem b <$>) . mapM readFile

dayItem :: Day -> [String] -> [(Day, String)]
dayItem b = ((b, "start") :) . map (\((_, e), i) -> (e, i)) . fromItemN b . map parse
