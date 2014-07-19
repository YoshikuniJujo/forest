{-# LANGUAGE FlexibleContexts, RankNTypes, PackageImports #-}

module Data.Pipe (
	PipeClass(..), Pipe, runPipe, onBreak, finalize, finally, bracket ) where

import Control.Applicative
import Control.Monad
import Control.Exception.Lifted (onException)
import Control.Monad.Trans.Control
import "monads-tf" Control.Monad.Trans

class PipeClass p where
	(=$=) :: Monad m => p a b m x -> p b c m y -> p a c m y
	yield :: Monad m => o -> p i o m ()
	await :: Monad m => p i o m (Maybe i)

data Pipe i o m r
	= Ready (m ()) o (Pipe i o m r)
	| Need (m ()) (Maybe i -> Pipe i o m r)
	| Done (m ()) r
	| Make (m ()) (m (Pipe i o m r))

finalizer :: Pipe i o m r -> m ()
finalizer (Ready f _ _) = f
finalizer (Need f _) = f
finalizer (Done f _) = f
finalizer (Make f _) = f

instance PipeClass Pipe where
	p =$= Done f r = Done (finalizer p >> f) r
	p =$= Ready f o p' = Ready f o $ p =$= p'
	Need f n =$= p = Need f $ \i -> n i =$= p
	Ready _ o p =$= Need _ n = p =$= n (Just o)
	Done f r =$= Need f' n =
		Done (return ()) r =$= Make f' (f >> return (n Nothing))
	Make f m =$= p = Make f $ (=$= p) `liftM` m
	p =$= Make f m = Make f $ (p =$=) `liftM` m

	yield x = Ready (return ()) x (return ())
	await = Need (return ()) return

instance Monad m => Monad (Pipe i o m) where
	Ready f o p >>= k = Ready f o $ p >>= k
	Need f n >>= k = Need f $ \i -> n i >>= k
--	Done f r >>= k = Make (return ()) $ f >> return (k r)
	Done _ r >>= k = k r
	Make f m >>= k = Make f $ (>>= k) `liftM` m
	return = Done (return ())

instance Monad m => Functor (Pipe i o m) where
	fmap = (=<<) . (return .)

instance Monad m => Applicative (Pipe i o m) where
	pure = return
	(<*>) = liftM2 id

instance MonadTrans (Pipe i o) where
	lift = liftP

instance MonadIO m => MonadIO (Pipe i o m) where
	liftIO = lift . liftIO

runPipe :: Monad m => Pipe i o m r -> m (Maybe r)
runPipe (Done f r) = f >> return (Just r)
runPipe (Make _ m) = runPipe =<< m
runPipe _ = return Nothing

liftP :: Monad m => m a -> Pipe i o m a
liftP m = Make (return ()) $ Done (return ()) `liftM` m

bracket :: MonadBaseControl IO m =>
	m a -> (a -> m b) -> (a -> Pipe i o m r) -> Pipe i o m r
bracket o c p = do
	h <- liftP o
	p h `finally` (c h >> return ())

onBreak :: Monad m => Pipe i o m r -> m b -> Pipe i o m r
onBreak (Ready f0 o p) f = Ready (f0 >> f >> return ()) o $ onBreak p f
onBreak (Need f0 n) f = Need (f0 >> f >> return ()) $ \i -> onBreak (n i) f
onBreak (Done f0 r) _ = Done f0 r
onBreak (Make f0 m) f = Make (f0 >> f >> return ()) $ flip onBreak f `liftM` m

finalize :: Monad m => Pipe i o m r -> m b -> Pipe i o m r
finalize (Ready f0 o p) f = Ready (f0 >> f >> return ()) o $ finalize p f
finalize (Need f0 n) f = Need (f0 >> f >> return ()) $ \i -> finalize (n i) f
finalize (Done f0 r) f = Done (f0 >> f >> return ()) r
finalize (Make f0 m) f = Make (f0 >> f >> return ()) $ flip finalize f `liftM` m

finally :: MonadBaseControl IO m => Pipe i o m r -> m b -> Pipe i o m r
finally p f = finalize (mapMake (`onException` f) p) f

mapMake :: Monad m => (forall a . m a -> m a) -> Pipe i o m r -> Pipe i o m r
mapMake k (Ready f o p) = Ready f o $ mapMake k p
mapMake k (Need f n) = Need f $ \i -> mapMake k $ n i
mapMake _ (Done f r) = Done f r
mapMake k (Make f m) = Make f . k $ mapMake k `liftM` m
