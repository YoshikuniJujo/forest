{-# LANGUAGE PackageImports #-}

import Control.Applicative
import "crypto-random" Crypto.Random
import Crypto.PubKey.DH

main :: IO ()
main = do
	gen <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	let (ps, _) = generateParams gen 512 2
	writeFile "dh-params.txt" $ show ps ++ "\n"
