{-# LANGUAGE FlexibleContexts #-}

import PipeF
import Control.Monad
import System.IO

import Control.Monad.IO.Class
import Control.Monad.Base

readStdin :: Pipe IO () Char ()
readStdin = do
	c <- liftP getChar
	liftP $ print c
	case c of
		'q' -> return ()
		_ -> yield c >> readStdin

toList :: Monad m => Pipe m a () [a]
toList = await >>= \mx -> case mx of
	Just x -> (x :) `liftM` toList
	_ -> return []

takeN :: Monad m => Int -> Pipe m a () [a]
takeN 0 = return []
takeN n = do
	mx <- await
	case mx of
		Just x -> (x :) `liftM` takeN (n - 1)
		_ -> return []

take1 :: Monad m => Pipe m a () (Maybe a)
take1 = do
	mx <- await
	return mx
	{-
	case mx of
		Just x -> return $ Just x
		_ -> return Nothing
		-}

readf :: FilePath -> Pipe IO () String ()
readf fp = bracket
	(openFile fp ReadMode) (\h -> putStrLn "finalize" >> hClose h) hRead

hRead :: Handle -> Pipe IO () String ()
hRead h = do
	eof <- liftP $ hIsEOF h
	if eof then return () else do
		l <- liftP $ hGetLine h
		yield l
		hRead h

bracket :: (MonadIO m, MonadBase m IO) =>
	m a -> (a -> m b) -> (a -> Pipe m i o r) -> Pipe m i o r
bracket o c p = do
	h <- liftP o
	p h `finalize'` (c h >> return ())
