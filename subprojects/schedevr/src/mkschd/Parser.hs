module Parser (
	parse, LES, Item, isOK, isLate, ending, contents,
	parseItemList) where

import Data.List
import Data.Time
import Data.Maybe
import Data.Char
import Control.Arrow

data LES = SmallerThan | NoLargerThan | Equal | NoSmallerThan | LargerThan | Always
	deriving (Show, Enum, Eq)

type Item = (((LES, Day), Integer), String)

isOK :: Item -> Day -> Bool
isOK (((les, d), _), _) = flip (op les) d

isLate :: Item -> Day -> Bool
isLate (((SmallerThan, d), _), _) = (d <=)
isLate (((NoLargerThan, d), _), _) = (d <)
isLate (((Equal, d), _), _) = (d <)
isLate _ = const False

ending :: Item -> Day -> Day
ending ((_, s), _) = addDays s

contents :: Item -> String
contents = snd

readLES :: String -> Maybe LES
readLES = flip lookup $ zip ["<", "<=", "=", ">=", ">", ""] [SmallerThan ..]

op :: LES -> (Day -> Day -> Bool)
op = fromJust . flip lookup (zip [SmallerThan ..]
	[(<), (<=), (==), (>=), (>), const $ const True])

parse :: String -> [Item]
parse = map parseLine . lines

parseLine :: String -> Item
parseLine str = case split (== ':') str of 
	[d, s, c] -> ((parseDay d, read s), c)
	_ -> error "bad number of fields of line"

split :: (Char -> Bool) -> String -> [String]
split s = unfoldr $ \xs -> case (xs, span (not . s) xs) of
	([], _) -> Nothing
	(_, (_, [])) -> Just (dropSpaces xs, [])
	(_, (r, _ : xs')) -> Just (dropSpaces r, xs')

parseDay :: String -> (LES, Day)
parseDay "" = (Always, read "0000-00-00")
parseDay s = (fromJust . readLES *** read) $ span (not . isDigit) s

dropSpaces :: String -> String
dropSpaces = reverse . dropWhile isSpace . reverse . dropWhile isSpace

parseItemList :: String -> (String, String)
parseItemList str = (is !! 0, is !! 2)
	where
	is = split (== ':') str
