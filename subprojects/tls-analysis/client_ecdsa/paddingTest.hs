{-# LANGUAGE PackageImports, OverloadedStrings #-}

import Control.Applicative
import "crypto-random" Crypto.Random
import Crypto.PubKey.RSA.PKCS15
import Crypto.PubKey.RSA
import qualified Data.ByteString as BS

getGen :: IO SystemRNG
getGen = cprgCreate <$> createEntropyPool

paddSome :: SystemRNG -> Either Error BS.ByteString
paddSome gen = fst <$> pad gen 256 "Hello, world!"
