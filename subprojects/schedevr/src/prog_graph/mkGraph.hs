import WatchEVR
import Graphics.X11.Turtle
import Data.List
import Data.Time
import Data.Maybe
import Control.Arrow
import Control.Applicative
import System.Environment
import System.FilePath
import Data.Char
import Data.Function
import ScheduleEVR
import System.Directory
import System.FilePath

evrItemsName, evrProgressName :: [FilePath]
evrItemsName = [
	"../test1/item_list",
	"../test2/item_list",
	"../test3/item_list" ]
evrProgressName = [
	"../test1/progress",
	"../test2/progress",
	"../test3/progress"]

schdFiles :: [FilePath]
schdFiles = [
	"../test1/test.schd",
	"../test2/test2.schd",
	"../test3/test3.schd" ]

getSchdFile :: FilePath -> IO [FilePath]
getSchdFile dir = do
	ls <- filter ((== ".schd") . takeExtension) <$> getDirectoryContents dir
	return $ map (dir </>) ls

getItemFiles, getProgressFiles :: [FilePath] -> [FilePath]
getItemFiles = map (</> "item_list")
getProgressFiles = map (</> "progress")

getSchdFiles :: [FilePath] -> IO [FilePath]
getSchdFiles = (concat <$>) . mapM getSchdFile

main :: IO ()
main = do
	"-s" : start : dirs <- getArgs
	eiCnt <- concat <$> mapM readFile (getItemFiles dirs)
	es <- dayItemFile (read start) =<< getSchdFiles dirs
	espCnt <- concat <$> mapM readFile (getProgressFiles dirs)
	let
		ei = map idPoint' $ lines eiCnt
		esp = sortBy (on compare fst) $ map dayId $ lines espCnt
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
	write t "Kochi Gothic" fontsize $ take 4 (show pc) ++ "% (" ++
		show (getPoint dip) ++ "/" ++ show (getPoint di) ++ ")"
	hideturtle t
	onkeypress f $ return . (/= 'q')
	waitField f
