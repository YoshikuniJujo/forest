{-# LANGUAGE PackageImports #-}

import "monads-tf" Control.Monad.Trans
import Data.Word8
import Data.Pipe
import Data.Pipe.List
import System.Environment

import qualified Data.ByteString as BS

import Lexer
import Papillon

main :: IO ()
main = do
	fn : _ <- getArgs
	cnt <- BS.readFile fn
	check sepTag [cnt]

notEmpty :: XmlEvent -> Bool
notEmpty (XECharData cd) = not $ BS.all isSpace cd
notEmpty _ = True

convert :: Monad m => (a -> b) -> Pipe a b m ()
convert f = await >>= maybe (return ()) (\x -> yield (f x) >> convert f)

filterP :: Monad m => (a -> Bool) -> Pipe a a m ()
filterP p = await >>=
	maybe (return ()) (\x -> (if p x then yield x else return ()) >> filterP p)

check :: (Monad m, MonadIO m) =>
	Pipe BS.ByteString BS.ByteString m () -> [BS.ByteString] -> m ()
check p bss = do
	mu <- runPipe $ fromList bss =$= p
		=$= convert parseXmlEvent
		=$= filterP (maybe True notEmpty)
		=$= puts
	case mu of
		Just _ -> return ()
		_ -> error "bad"

puts :: Show a => (Monad m, MonadIO m) => Pipe a () m ()
puts = await >>= maybe (return ()) (\bs -> liftIO (print bs) >> puts)
