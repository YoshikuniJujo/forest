{-# LANGUAGE PackageImports #-}

import "monads-tf" Control.Monad.State
import Control.Concurrent.STM

count :: StateT Int IO ()
count = modify succ

stateToStm :: StateT s IO a -> TVar s -> IO a
stateToStm m v = do
	s <- atomically $ readTVar v
	(r, s') <- m `runStateT` s
	atomically $ writeTVar v s'
	return r
