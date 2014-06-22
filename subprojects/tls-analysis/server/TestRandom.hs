{-# LANGUAGE OverloadedStrings, PackageImports #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module TestRandom (StdGen) where

import System.Random (RandomGen(..), random, StdGen, mkStdGen)
import "crypto-random" Crypto.Random (CPRG(..))

import qualified Data.ByteString as BS

instance CPRG StdGen where
	cprgCreate _ = mkStdGen 4492
	cprgSetReseedThreshold = undefined
	cprgFork = split
	cprgGenerate = randomByteString
	cprgGenerateWithEntropy = randomByteString

randomByteString :: Int -> StdGen -> (BS.ByteString, StdGen)
randomByteString 0 g = ("", g)
randomByteString n g = (w `BS.cons` bs, g'')
	where
	(w, g') = random g
	(bs, g'') = randomByteString (n - 1) g'
