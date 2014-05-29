{-# LANGUAGE PackageImports #-}

import Control.Applicative
import "crypto-random" Crypto.Random
import Crypto.PubKey.DH
import Data.IORef
import System.IO.Unsafe

gen :: IORef SystemRNG
gen = unsafePerformIO $ newIORef =<< cprgCreate <$> createEntropyPool

params :: Params
params = unsafePerformIO $ do
	g <- readIORef gen
	let (ps, g') = generateParams g 8 2
	writeIORef gen g'
	return ps

main :: IO ()
main = do
	print $ getShared params (fst alice) (snd bob)
	print $ getShared params (fst bob) (snd alice)

alice :: (PrivateNumber, PublicNumber)
alice = unsafePerformIO $ do
	g <- readIORef gen
	let (pr, g') = generatePrivate g params
	writeIORef gen g'
	return (pr, calculatePublic params pr)

bob :: (PrivateNumber, PublicNumber)
bob = unsafePerformIO $ do
	g <- readIORef gen
	let (pr, g') = generatePrivate g params
	writeIORef gen g'
	return (pr, calculatePublic params pr)
