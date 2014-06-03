{-# LANGUAGE OverloadedStrings #-}

import Prelude hiding (map)

import Network
import Data.Conduit
import Data.Conduit.List
import Data.Conduit.Binary
import Data.ByteString (ByteString)
import Data.ByteString.Char8 (pack)
import System.IO
import Text.XML.Stream.Parse

main :: IO ()
main = do
	sourceHandle stdin
		=$= checkQuit
--		=$= parseBytes def
		=$= map (pack . show)
		$$ sinkHandle stdout
--	sourceHandle stdin =$= checkQuit $$ sinkNull

checkQuit :: Monad m => Conduit ByteString m ByteString
checkQuit = do
	mln <- await
	case mln of
		Just "quit\n" -> return ()
		Just ln -> do
			yield ln
			checkQuit
		_ -> return ()
