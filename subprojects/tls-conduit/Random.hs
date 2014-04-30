module Random (Random, random, randomToByteString) where

import Prelude hiding (take)
import Numeric

import Data.Conduit
import Data.Conduit.Binary

import Data.ByteString.Lazy (toStrict)
import qualified Data.ByteString as BS

data Random = Random BS.ByteString

showRandom :: Random -> String
showRandom (Random bs) = "(Random " ++
	unwords (map (pad 2 . flip showHex "") $ BS.unpack bs) ++ ")"

pad :: Int -> String -> String
pad n s = replicate (n - length s) '0' ++ s

instance Show Random where
	show = showRandom

random :: Monad m => Consumer BS.ByteString m Random
random = do
	bs <- take 32
	return $ Random $ toStrict bs

randomToByteString :: Random -> BS.ByteString
randomToByteString (Random bs) = bs
