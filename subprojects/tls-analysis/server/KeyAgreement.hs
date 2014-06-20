{-# LANGUAGE TypeFamilies, PackageImports #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module KeyAgreement (Base(..), dhdebug, dhparams, secp256r1, curve) where

import Control.Applicative ((<$>), (<*>))
import Control.Arrow (first)
import Data.Word (Word8, Word16)
import Data.IORef (IORef, newIORef, readIORef)
import System.IO.Unsafe (unsafePerformIO)
import "crypto-random" Crypto.Random (CPRG(..), SystemRNG, createEntropyPool)

import qualified Data.ByteString as BS
import qualified Codec.Bytable as B
import qualified Crypto.Types.PubKey.DH as DH
import qualified Crypto.PubKey.DH as DH
import qualified Crypto.Types.PubKey.ECC as ECC
import qualified Crypto.PubKey.ECC.Prim as ECC

dhdebug :: IORef Bool
dhdebug = unsafePerformIO $ newIORef False

dhparams :: DH.Params
dhparams = unsafePerformIO $ do
	d <- readIORef dhdebug
	if d then return debugParams else do
		g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
		let	(ps, _g') = DH.generateParams g 512 2
		return ps

debugParams :: DH.Params
debugParams = DH.Params {
	DH.params_p = read $
		"1338867040638478005227332281355557889931" ++
		"1962650086248796400859707491197838151676" ++
		"6506863771256718760127048339751075586727" ++
		"62206289243982143448691649139121243",
	DH.params_g = 2 }

curve :: ECC.Curve
curve = fst (generateBase undefined () :: (ECC.Curve, SystemRNG))

secp256r1 :: ECC.Curve
secp256r1 = ECC.CurveFP $ ECC.CurvePrime p (ECC.CurveCommon a b g n h)
	where
	p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
	a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
	b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
	g = ECC.Point gx gy
	gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
	gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
	n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
	h = 0x01

class Base b where
	type Param b
	type Secret b
	type Public b
	generateBase :: CPRG g => g -> Param b -> (b, g)
	generateSecret :: CPRG g => b -> g -> (Secret b, g)
	calculatePublic :: b -> Secret b -> Public b
	calculateCommon :: b -> Secret b -> Public b -> BS.ByteString

instance Base DH.Params where
	type Param DH.Params = (Int, Integer)
	type Secret DH.Params = DH.PrivateNumber
	type Public DH.Params = DH.PublicNumber
	generateBase rng (bits, gen) = DH.generateParams rng bits gen
	generateSecret = flip DH.generatePrivate
	calculatePublic = DH.calculatePublic
	calculateCommon ps sn pn = B.toByteString .
		(\(DH.SharedKey i) -> i) $ DH.getShared ps sn pn

instance B.Bytable DH.Params where
	fromByteString = B.evalBytableM $ DH.Params <$> B.take 2 <*> B.take 2
	toByteString (DH.Params dhP dhG) = BS.concat [
		B.addLength (undefined :: Word16) $ B.toByteString dhP,
		B.addLength (undefined :: Word16) $ B.toByteString dhG ]

instance B.Bytable DH.PublicNumber where
	fromByteString = B.evalBytableM $ fromInteger <$> (B.take =<< B.take 2)
	toByteString = B.addLength (undefined :: Word16) .
		B.toByteString . \(DH.PublicNumber pn) -> pn

instance Base ECC.Curve where
	type Param ECC.Curve = ()
	type Secret ECC.Curve = Integer
	type Public ECC.Curve = ECC.Point
	generateBase g _ = (secp256r1, g)
	generateSecret _ g =
		(either error id . B.fromByteString) `first` cprgGenerate 32 g
	calculatePublic c s = ECC.pointMul c s (ECC.ecc_g $ ECC.common_curve c)
	calculateCommon c sn pp =
		let ECC.Point x _ = ECC.pointMul c sn pp in B.toByteString x

instance B.Bytable ECC.Point where
	fromByteString bs = case BS.uncons $ BS.tail bs of
		Just (4, rest) -> Right $ let (x, y) = BS.splitAt 32 rest in
			ECC.Point	(either error id $ B.fromByteString x)
					(either error id $ B.fromByteString y)
		_ -> Left "KeyAgreement.hs: ECC.Point.fromByteString"
	toByteString (ECC.Point x y) = B.addLength (undefined :: Word8) .
		BS.cons 4 $ BS.append (B.toByteString x) (B.toByteString y)
	toByteString ECC.PointO = error "KeyAgreement.hs: EC.Point.toByteString"
