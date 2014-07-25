{-# LANGUAGE PackageImports #-}

import "monads-tf" Control.Monad.Trans
import Data.Word8
import Data.Pipe
import Data.Pipe.List
import System.Environment

import qualified Data.ByteString as BS

import XmlEvent

main :: IO ()
main = do
	fn : _ <- getArgs
	cnt <- BS.readFile fn
	mu <- runPipe $ fromList [cnt] =$= xmlEvent =$= puts
	case mu of
		Just _ -> return ()
		_ -> error "bad"

puts :: Show a => (Monad m, MonadIO m) => Pipe a () m ()
puts = await >>= maybe (return ()) (\bs -> liftIO (print bs) >> puts)
