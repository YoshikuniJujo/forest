module Data.Pipe.List (
	fromList,
	toList,
	) where

import Control.Applicative
import Data.Pipe

fromList :: Monad m => [a] -> Pipe () a m ()
fromList [] = return ()
fromList (x : xs) = yield x >> fromList xs

-- | Consume all values from the stream and return as a list.
-- This will pull all values into memory.

toList :: Monad m => Pipe a () m [a]
toList = do
	mx <- await
	case mx of
		Just x -> (x :) <$> toList
		_ -> return []
