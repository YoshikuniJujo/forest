{-# LANGUAGE PackageImports, TypeFamilies #-}

module Base (Base(..)) where

import qualified Data.ByteString as BS
import "crypto-random" Crypto.Random

class Base b where
	type Param b
	type Secret b
	type Public b
	generateBase :: CPRG g => g -> Param b -> (b, g)
	generateSecret :: CPRG g => g -> b -> (Secret b, g)
	calculatePublic :: b -> Secret b -> Public b
	calculateCommon :: b -> Secret b -> Public b -> BS.ByteString

	encodeBasePublic :: b -> Public b -> BS.ByteString
	decodeBasePublic :: BS.ByteString -> Either String ((b, Public b), BS.ByteString)
	encodePublic :: b -> Public b -> BS.ByteString
	decodePublic :: b -> BS.ByteString -> Either String (Public b)

	wantPublic :: b -> Bool
	passPublic :: b -> Bool
