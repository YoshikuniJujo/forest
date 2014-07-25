{-# LANGUAGE PackageImports #-}

import Control.Monad
import "monads-tf" Control.Monad.Trans
import Data.Pipe
import Data.Pipe.List
import System.Environment

import qualified Data.ByteString as BS

import XmlCreate

main :: IO ()
main = do
	fn : _ <- getArgs
	cnt <- BS.readFile fn
	mu <- runPipe $ fromList [cnt]
		=$= xmlEvent
		=$= filterJust
--		=$= (xmlBegin >>= xmlNode)
		=$= xmlPipe
		=$= puts
	case mu of
		Just _ -> return ()
		_ -> error "bad in main"

xmlPipe :: Monad m => Pipe XmlEvent XmlNode m ()
xmlPipe = do
	c <- xmlBegin >>= xmlNode
	when c $ xmlPipe

puts :: Show a => (Monad m, MonadIO m) => Pipe a () m ()
puts = await >>= maybe (return ()) (\bs -> liftIO (print bs) >> puts)

filterJust :: Monad m => Pipe (Maybe a) a m ()
filterJust = do
	mmx <- await
	case mmx of
		Just (Just x) -> yield x >> filterJust
		Just _ -> error "filterJust" -- filterJust
		_ -> return ()
