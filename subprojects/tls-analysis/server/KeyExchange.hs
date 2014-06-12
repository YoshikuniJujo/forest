{-# LANGUAGE TypeFamilies, PackageImports #-}

module KeyExchange (Base(..)) where

import "crypto-random" Crypto.Random (CPRG)
import qualified Data.ByteString as BS

class Base b where
	type Param b
	type Secret b
	type Public b
	generateBase :: CPRG g => g -> Param b -> (b, g)
	generateSecret :: CPRG g => g -> b -> (Secret b, g)
	calculatePublic :: b -> Secret b -> Public b
	calculateCommon :: b -> Secret b -> Public b -> BS.ByteString
