module WatchEVR (
	idPoint', dayId, accumSecond, dayPoint, getConverter, progPercent,
	waku, chart, fontsize
) where

import Graphics.X11.Turtle
import Data.List
import Data.Time
import Data.Maybe
import Control.Arrow
import System.Environment
import System.FilePath
import Data.Char

evrItemsName, evrScheduleName, evrProgressName :: FilePath
-- evrItemsName = "evr_items.txt"
evrItemsName = "item_list"
evrScheduleName = "evr_schedule"
evrProgressName = "progress"

main :: IO ()
main = do
	prog <- getProgName
	path <- getExecutablePath
	let dir = takeDirectory path ++ "/"
	eiCnt <- readFile $ dir ++ evrItemsName
	esCnt <- readFile $ dir ++ evrScheduleName
	espCnt <- readFile $ dir ++ evrProgressName
	let
--		ei = map idPoint $ tail $
--			dropWhile (not . isPrefixOf "* タイトル") $ lines eiCnt
		ei = map idPoint' $ lines eiCnt
		es = map dayId $ lines esCnt
		esp = map dayId $ lines espCnt
		di = accumSecond (+) 0 $ dayPoint ei es
		dip = accumSecond (+) 0 $ dayPoint ei esp
		cnv = getConverter (50, 100) (400, 200) di
		pc = progPercent dip di
	f <- openField
	topleft f
	t <- newTurtle f
	speed t "fastest"
	flushoff t
	waku t (50, 100) (400, 200) di
	goto t 50 300
	flushon t
	speed t "slowest"
	chart t "grey" cnv (50, 100) (400, 200) di
	speed t "slow"
	goto t 50 300
	speed t "slowest"
	chart t "black" cnv (50, 100) (400, 200) dip
	speed t "fastest"
	goto t 200 100
	write t "Kochi Gothic" fontsize $ take 4 (show pc) ++ "%"
	hideturtle t
	onkeypress f $ return . (/= 'q')
	waitField f

progPercent :: [(Day, Int)] -> [(Day, Int)] -> Double
progPercent p s = 100 *
	fromIntegral (getPoint p) / fromIntegral (getPoint s)

getPoint :: [(Day, Int)] -> Int
getPoint = snd . last

idPoint :: String -> (String, Int)
idPoint ln = (i, read $ dropWhile (== '\t') p)
	where
	(i, p) = span (/= '\t') $ dropWhile (== '\t') $ dropWhile (/= '\t') ln

idPoint' :: String -> (String, Int)
idPoint' str = (is !! 0, read $ is !! 1)
	where
	is = split ':' str

split :: Char -> String -> [String]
split _ "" = []
split c str = case span (/= c) str of
	(s, "") -> [deleteSpaces s]
	(s, _ : r) -> deleteSpaces s : split c r

deleteSpaces :: String -> String
deleteSpaces = reverse . dropWhile isSpace . reverse . dropWhile isSpace

dayId :: String -> (Day, String)
dayId ln = (read d, i)
	where
	(i, d) = span (/= '\t') ln

dayPoint :: [(String, Int)] -> [(Day, String)] -> [(Day, Int)]
dayPoint tbl = map $ second $ fromJust . flip lookup tbl

accumSecond :: (c -> b -> c) -> c -> [(a, b)] -> [(a, c)]
accumSecond op r0 [] = []
accumSecond op r0 ((x1, y1) : ps) =
	(x1, r0 `op` y1) : accumSecond op (r0 `op` y1) ps

fontsize = 10

chart :: (Enum x, Enum y, Ord x, Show x, ColorClass c) => Turtle -> c ->
	((x, y) -> (Double, Double)) ->
	(Double, Double) -> (Double, Double) -> [(x, y)] -> IO ()
chart t c converter tl@(left, top) wh@(width, height) dt = do
	pencolor t c
	turtleChart t $ map converter dt
	penup t

waku t tl@(left, top) wh@(width, height) dt = do
		penup t
		goto t left (top + height)
		pendown t
		goto t (left + width) (top + height)
		penup t
		goto t left (top + height)
		pendown t
		goto t left top
		penup t
		goto t (left - fontsize * 2) (top + height + fontsize * 1.5)
		write t "Kochi Gothic" fontsize $ show minx
		goto t (left + width - fontsize * 2) (top + height + fontsize * 1.5)
		write t "Kochi Gothic" fontsize $ show maxx
	where
	minx = minimum $ map fst dt
	maxx = maximum $ map fst dt

turtleChart :: Turtle -> [(Double, Double)] -> IO ()
turtleChart t ((x0, y0) : ps) = do
	penup t
	goto t x0 y0
	pendown t
	mapM_ (uncurry $ goto t) ps

getConverter :: (Enum x, Enum y) => (Double, Double) -> (Double, Double) ->
	[(x, y)] -> (x, y) -> (Double, Double)
getConverter (left, top) (width, height) ps = convertx *** converty
	where
	maxx = maximum $ map (fromEnum . fst) ps
	minx = minimum $ map (fromEnum . fst) ps
	maxy = maximum $ map (fromEnum . snd) ps
	miny = minimum $ map (fromEnum . snd) ps
	convertx x = left +
		(fromIntegral $ fromEnum x - minx) /
		(fromIntegral $ maxx - minx) * width
	converty y = top + height -
		(fromIntegral $ fromEnum y - miny) /
		(fromIntegral $ maxy - miny) * height
