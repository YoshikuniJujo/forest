module Output (
	Output, showOutputs, evrOutputs, fromItem, fromItem2, fromItemN
) where

import Parser
import Data.Time
import System.Locale

type Output = ((Day, Day), String)

evrOutputs :: [Output] -> String
evrOutputs = unlines . map evrOutput

evrOutput :: Output -> String
evrOutput ((_, e), i) = i ++ "\t" ++ show e

showOutputs :: [Output] -> String
showOutputs = unlines . map showOutput

showOutput :: Output -> String
showOutput ((b, e), c)
	| b >= e = showDay b ++ replicate 7 ' ' ++ c
	| otherwise = showDay b ++ "-" ++ showDay e ++ " " ++ c
	where
	showDay = formatTime defaultTimeLocale "%m/%d"

fromItem :: Day -> [Item] -> [Output]
fromItem _ [] = []
fromItem d ia@(i : is)
	| isOK i d = ((d, pred $ ending i d), contents i) : fromItem (ending i d) is
	| isLate i d = error "too late"
	| otherwise = fromItem (succ d) ia

fromItem2 :: Day -> [Item] -> [Item] -> [Output]
fromItem2 d ia1 [] = fromItem d ia1
fromItem2 d [] ia2 = fromItem d ia2
fromItem2 d ia1@(i1 : is1) ia2@(i2 : is2)
--	| isLate i1 e2 && isLate i2 e1 = error "too late"
	| isOK i1 d && isLate i2 e1 =
		((d, pred e1), contents i1) : fromItem2 e1 is1 ia2
	| isLate i1 e2 && isOK i2 d =
		((d, pred e2), contents i2) : fromItem2 e2 is2 ia1
	| isOK i1 d =
		((d, pred e1), contents i1) : fromItem2 e1 is1 ia2
	| isOK i2 d =
		((d, pred e2), contents i2) : fromItem2 e2 is2 ia1
	| not (isLate i1 d) && not (isLate i2 d) = fromItem2 (succ d) ia1 ia2
	| otherwise = error "too late"
	where
	e1 = ending i1 d
	e2 = ending i2 d

fromItemN :: Day -> [[Item]] -> [Output]
fromItemN _ [] = []
fromItemN d ias
	| any null ias = fromItemN d $ filter (not . null) ias
	| any (flip isLate d) (map head ias) = error "too late"
fromItemN d ias = fromItemNSelect [] d es diag ias
	where
	es = map (flip ending d . head) ias
	diag = diagonal $ map head ias

fromItemNSelect :: [[Item]] -> Day -> [Day] -> [[Item]] -> [[Item]] -> [Output]
fromItemNSelect pre d [] [] [] = fromItemN (succ d) pre
fromItemNSelect pre d (e : es) (diag : diags) ((i : is) : ias)
	| check d i e diag =
		((d, pred e), contents i) : fromItemN e (is : pre ++ ias)
fromItemNSelect pre d (e : es) (diag : diags) (ia : ias) =
	fromItemNSelect (ia : pre) d es diags ias

diagonal :: [a] -> [[a]]
diagonal xs = map (\i -> take i xs ++ drop (i + 1) xs) [0 .. length xs - 1]

check :: Day -> Item -> Day -> [Item] -> Bool
check d i e diags = isOK i d && all (not . flip isLate e) diags
