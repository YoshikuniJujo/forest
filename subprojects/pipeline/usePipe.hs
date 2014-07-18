import PipeF
import Control.Monad
import System.IO

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
readf fp = do
	h <- liftP $ openFile fp ReadMode
	hRead h `finalize'` (putStrLn "finalize" >> hClose h)

hRead :: Handle -> Pipe IO () String ()
hRead h = do
	eof <- liftP $ hIsEOF h
	if eof then return () else do
		l <- liftP $ hGetLine h
		yield l
		hRead h
