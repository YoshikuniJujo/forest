{-# LANgUAGE FlexibleContexts, PackageImports #-}

import "monads-tf" Control.Monad.State
import qualified System.IO.Unsafe as U
import Control.Monad.Trans.Control

unsafeInterleaveIO :: MonadBaseControl IO m => m a -> m a
unsafeInterleaveIO m = control $ \runInIO -> U.unsafeInterleaveIO (runInIO m)

(>>>) :: MonadBaseControl IO m => m a -> m b -> m b
m1 >>> m2 = unsafeInterleaveIO m1 >> m2

example :: StateT [Int] IO ()
example = unsafeInterleaveIO $
	push 3 >>> push 33 >>> push 95 >>> push 66 >>> push 72

push :: Int -> StateT [Int] IO ()
push i = do
	lift . putStrLn $ "push " ++ show i
	modify (i :)

-- example2 :: StateT [Int] IO ()
-- example2 = unsafeInterleaveIO $
