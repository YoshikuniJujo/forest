{-# LANGUAGE OverloadedStrings #-}

module Ecdsa (blindSign, generateKs) where

import Control.Applicative ((<$>), (<*>))
import Data.Maybe (mapMaybe)
import Data.Bits (shiftR, xor)
import Crypto.Number.ModArithmetic (inverse)

import qualified Data.ByteString as BS
import qualified Codec.Bytable as B
import Codec.Bytable.BigEndian ()
import qualified Crypto.Types.PubKey.ECC as ECC
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA

type Hash = BS.ByteString -> BS.ByteString

blindSign :: Integer -> Hash -> ECDSA.PrivateKey -> [Integer] ->
	BS.ByteString -> ECDSA.Signature
blindSign bl hs sk ks m =
	head $ (`mapMaybe` ks) $ \k -> blindSign_ bl hs sk k m

blindSign_ :: Integer -> Hash -> ECDSA.PrivateKey -> Integer ->
	BS.ByteString -> Maybe ECDSA.Signature
blindSign_ bl hs (ECDSA.PrivateKey crv d) k m = do
	e <- either (const Nothing) return . B.fromByteString $ hs m
	let	dl = qlen e - qlen n
		z = (if dl > 0 then (`shiftR` dl) else id) e
	r <- case bPointMul bl crv k g of
		ECC.PointO -> Nothing
		ECC.Point 0 _ -> Nothing
		ECC.Point x _ -> return $ x `mod` n
	ki <- inverse k n
	case ki * (z + r * d) `mod` n of
		0 -> Nothing
		s -> return $ ECDSA.Signature r s
	where
	ECC.CurveCommon _ _ g n _ = ECC.common_curve crv

bPointMul :: Integer -> ECC.Curve -> Integer -> ECC.Point -> ECC.Point
bPointMul bl c@(ECC.CurveFP (ECC.CurvePrime _ cc)) k p =
	ECC.pointMul c (bl * ECC.ecc_n cc + k) p
bPointMul _ _ _ _ = error "Ecdsa.bPointMul: not implemented"

-- RFC 6979

qlen :: Integer -> Int
qlen 0 = 0
qlen q = succ . qlen $ q `shiftR` 1

rlen :: Integer -> Int
rlen 0 = 0
rlen q = 8 + rlen (q `shiftR` 8)

blen :: BS.ByteString -> Int
blen = (8 *) . BS.length

bits2int :: Integer -> BS.ByteString -> Integer
bits2int q bs
	| ql < bl = i `shiftR` (bl - ql)
	| otherwise = i
	where
	ql = qlen q
	bl = blen bs
	i = either error id (B.fromByteString bs)

int2octets :: Integer -> Integer -> BS.ByteString
int2octets q i
	| bsl <= l0 = BS.replicate (l0 - bsl) 0 `BS.append` bs
	| otherwise = error "Functions.int2octets: too large integer"
	where
	rl = rlen q
	l0 = rl `div` 8
	bs = B.toByteString i
	bsl = BS.length bs

bits2octets :: Integer -> BS.ByteString -> BS.ByteString
bits2octets q bs = int2octets q z2
	where
	z1 = bits2int q bs
	z2 = z1 `mod` q

hmac :: Integral t => (BS.ByteString -> BS.ByteString) -> t ->
	BS.ByteString -> BS.ByteString -> BS.ByteString
hmac f bl secret msg =
    f $! BS.append opad (f $! BS.append ipad msg)
  where opad = BS.map (xor 0x5c) k'
        ipad = BS.map (xor 0x36) k'

        k' = BS.append kt pad
          where kt  = if BS.length secret > fromIntegral bl then f secret else secret
                pad = BS.replicate (fromIntegral bl - BS.length kt) 0

initV :: BS.ByteString -> BS.ByteString
initV h = BS.replicate (BS.length h) 1

initK :: BS.ByteString -> BS.ByteString
initK h = BS.replicate (BS.length h) 0

initializeKV :: (Hash, Int) ->
	Integer -> Integer -> BS.ByteString -> (BS.ByteString, BS.ByteString)
initializeKV (hs, bl) q x h = (k2, v2)
	where
	v0 = initV h
	k0 = initK h
	k1 = hmac hs bl k0 $ BS.concat
		[v0, "\x00", int2octets q x, bits2octets q h]
	v1 = hmac hs bl k1 v0
	k2 = hmac hs bl k1 $ BS.concat
		[v1, "\x01", int2octets q x, bits2octets q h]
	v2 = hmac hs bl k2 v1

createT :: (Hash, Int) -> Integer -> BS.ByteString -> BS.ByteString ->
	BS.ByteString -> (BS.ByteString, BS.ByteString)
createT hsbl@(hs, bl) q k v t
	| blen t < qlen q = createT hsbl q k v' $ t `BS.append` v'
	| otherwise = (t, v)
	where
	v' = hmac hs bl k v

createKs :: (Hash, Int) -> Integer -> BS.ByteString -> BS.ByteString -> [Integer]
createKs hsbl@(hs, bls) q k v = kk : createKs hsbl q k' v''
	where
	(t, v') = createT hsbl q k v ""
	kk = bits2int q t
	k' = hmac hs bls k $ v' `BS.append` "\x00"
	v'' = hmac hs bls k' v'

generateKs :: (Hash, Int) -> Integer -> Integer -> BS.ByteString -> [Integer]
generateKs hsbl@(hs, _) q x m =
	filter ((&&) <$> (> 0) <*> (< q)) $  createKs hsbl q k v
	where
	h = hs m
	(k, v) = initializeKV hsbl q x h
