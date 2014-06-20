{-# LANGUAGE TypeFamilies, PackageImports #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module KeyAgreement (DhParam(..)) where

import Control.Arrow (first)
import "crypto-random" Crypto.Random (CPRG(..))

import qualified Data.ByteString as BS
import qualified Codec.Bytable as B
import qualified Crypto.Types.PubKey.DH as DH
import qualified Crypto.PubKey.DH as DH
import qualified Crypto.Types.PubKey.ECC as ECC
import qualified Crypto.PubKey.ECC.Prim as ECC

class DhParam b where
	type Secret b
	type Public b
	generateSecret :: CPRG g => b -> g -> (Secret b, g)
	calculatePublic :: b -> Secret b -> Public b
	calculateShared :: b -> Secret b -> Public b -> BS.ByteString

instance DhParam DH.Params where
	type Secret DH.Params = DH.PrivateNumber
	type Public DH.Params = DH.PublicNumber
	generateSecret = flip DH.generatePrivate
	calculatePublic = DH.calculatePublic
	calculateShared ps sn pn = B.toByteString .
		(\(DH.SharedKey i) -> i) $ DH.getShared ps sn pn

instance DhParam ECC.Curve where
	type Secret ECC.Curve = Integer
	type Public ECC.Curve = ECC.Point
	generateSecret _ =
		first (either error id . B.fromByteString) . cprgGenerate 32
	calculatePublic cv sn =
		ECC.pointMul cv sn (ECC.ecc_g $ ECC.common_curve cv)
	calculateShared cv sn pp =
		let ECC.Point x _ = ECC.pointMul cv sn pp in B.toByteString x
