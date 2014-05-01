{-# LANGUAGE PackageImports, ScopedTypeVariables, OverloadedStrings #-}

import Control.Applicative

import Data.X509
import Data.X509.File
import Crypto.PubKey.RSA
import Crypto.PubKey.RSA.PKCS15
import "crypto-random" Crypto.Random

main :: IO ()
main = do
	[PrivKeyRSA priv] <- readKeyFile "localhost.key"
	let pub = private_pub priv
	print priv
	print pub
	(gen :: SystemRNG) <- cprgCreate <$> createEntropyPool
	let (Right e, gen') = encrypt gen pub "Hello, world!"
	print e
	let Right d = decrypt Nothing priv e
	print d
