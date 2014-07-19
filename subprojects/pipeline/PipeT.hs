{-# LANGUAGE FlexibleContexts, RankNTypes, PackageImports #-}

module PipeT (
	Pipe, runPipe, (=$=), yield, await, finalize, finalize',
	bracketP,
	) where

import Control.Monad
import Control.Monad.Base
import Control.Monad.IO.Class
import Control.Exception
import "monads-tf" Control.Monad.Trans

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

p =$= Done f r = Done (finalizer p >> f) r
p =$= Ready f o p' = Ready f o $ p =$= p'
Need f n =$= p = Need f $ \i -> n i =$= p
Ready _ o p =$= Need _ n = p =$= n (Just o)
Done f r =$= Need f' n =
	Done (return ()) r =$= Make f' (f >> return (n Nothing))
Make f m =$= p = Make f $ (=$= p) `liftM` m
p =$= Make f m = Make f $ (p =$=) `liftM` m

instance Monad m => Monad (Pipe i o m) where
	Ready f o p >>= k = Ready f o $ p >>= k
	Need f n >>= k = Need f $ \i -> n i >>= k
--	Done f r >>= k = Make (return ()) $ f >> return (k r)
	Done _ r >>= k = k r
	Make f m >>= k = Make f $ (>>= k) `liftM` m
	return = Done (return ())

instance MonadTrans (Pipe i o) where
	lift = liftP

runPipe :: Monad m => Pipe i o m r -> m (Maybe r)
runPipe (Done f r) = f >> return (Just r)
runPipe (Make _ m) = runPipe =<< m
runPipe _ = return Nothing

liftP :: Monad m => m a -> Pipe i o m a
liftP m = Make (return ()) $ Done (return ()) `liftM` m

yield :: Monad m => o -> Pipe i o m ()
yield x = Ready (return ()) x (return ())

await :: Monad m => Pipe i o m (Maybe i)
await = Need (return ()) return

bracketP :: (MonadIO m, MonadBase m IO) =>
	m a -> (a -> m b) -> (a -> Pipe i o m r) -> Pipe i o m r
bracketP o c p = do
	h <- liftP o
	p h `finalize'` (c h >> return ())

finalize :: Monad m => Pipe i o m r -> m () -> Pipe i o m r
finalize (Ready _ o p) f = Ready f o $ finalize p f
finalize (Need _ n) f = Need f $ \i -> finalize (n i) f
finalize (Done _ r) f = Done f r
finalize (Make _ m) f = Make f $ flip finalize f `liftM` m

finalize' :: (MonadIO m, MonadBase m IO) => Pipe i o m r -> m () -> Pipe i o m r
finalize' p f =
	finalize (mapMake (liftIO . (`onException` liftBase f) . liftBase) p) f

mapMake :: Monad m => (forall a . m a -> m a) -> Pipe i o m r -> Pipe i o m r
mapMake k (Ready f o p) = Ready f o $ mapMake k p
mapMake k (Need f n) = Need f $ \i -> mapMake k $ n i
mapMake _ (Done f r) = Done f r
mapMake k (Make f m) = Make f . k $ mapMake k `liftM` m
