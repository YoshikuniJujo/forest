import Control.Applicative
import Control.Monad
import System.IO
import System.Directory
import System.FilePath
import Data.List

main :: IO ()
main = do
	nms <- map ("test" </>) . nub . sort . map dropExtensions .
		filter (`notElem` [".", ".."]) <$> getDirectoryContents "test"
	forM_ nms $ \nm -> do
		cltSz <- openFile (nm <.> "clt") ReadMode >>= hFileSize
		srvSz <- openFile (nm <.> "srv") ReadMode >>= hFileSize
		when (cltSz == 0 && srvSz == 0) $
			mapM_ removeFile $ map (nm <.>) ["css", "clt", "srv"]
