module Ecdsa (blindSign) where

import Crypto.Number.ModArithmetic
import Control.Monad
import Data.Bits
import Crypto.PubKey.ECC.ECDSA
import Crypto.Types.PubKey.ECC
import Crypto.PubKey.ECC.Prim
import qualified Codec.Bytable as B
import Codec.Bytable.BigEndian ()
import qualified Data.ByteString as BS

flp :: Point -> Point
flp (Point x y) = Point x $ - y
flp PointO = PointO

qlen 0 = 0
qlen n = 1 + qlen (n `shiftR` 1)

adjustLen k n = k * 2 ^ (qlen n - qlen k) + 1

cPointMul :: Curve -> Integer -> Point -> Point
cPointMul c@(CurveFP (CurvePrime _ cc)) k p = pointMul c (adjustLen k n * n + k) p
	where
	n = ecc_n cc

type Hash = BS.ByteString -> BS.ByteString

blindSign :: Integer -> PrivateKey -> Hash -> BS.ByteString ->
	Maybe Signature
blindSign k (PrivateKey curve d) hash msg = do
	let	CurveCommon _ _ g n _ = common_curve curve
		mul = cPointMul curve
		add = pointAdd curve
		z = tHash hash msg n
		point = k `mul` g
	r <- case point of
		PointO -> Nothing
		Point x _ -> return $ x `mod` n
	kInv <- inverse k n
	let s = kInv * (z + r * d) `mod` n
	when (r == 0 || s == 0) Nothing
	return $ Signature r s

blindSign_ :: Integer -> Integer -> PrivateKey -> Hash -> BS.ByteString ->
	Maybe Signature
blindSign_ bl k (PrivateKey curve d) hash msg = do
	let	CurveCommon _ _ g n _ = common_curve curve
		mul = pointMul curve
		add = pointAdd curve
		z = tHash hash msg n
		bp = bl `mul` g
		bpoint = k `mul` (g `add` bp)
		point = bpoint `add` flp (k `mul` bp)
	r <- case point of
		PointO -> Nothing
		Point x _ -> return $ x `mod` n
	kInv <- inverse k n
	let s = kInv * (z + r * d) `mod` n
	when (r == 0 || s == 0) Nothing
	return $ Signature r s

tHash :: (BS.ByteString -> BS.ByteString) -> BS.ByteString -> Integer -> Integer
tHash hs m n
	| d > 0 = e `shiftR` d
	| otherwise = e
	where
	Right e = B.fromByteString $ hs m
	d = myLog2 e - myLog2 n

myLog2 :: Integer -> Int
myLog2 0 = 0
myLog2 n = 1 + myLog2 (n `shiftR` 1)