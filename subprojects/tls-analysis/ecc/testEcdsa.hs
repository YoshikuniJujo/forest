import Crypto.Number.ModArithmetic
import Control.Monad
import Data.Bits
import Crypto.PubKey.ECC.ECDSA
import Crypto.Types.PubKey.ECDSA
import Crypto.Types.PubKey.ECC
import Crypto.PubKey.ECC.Prim
import Crypto.Hash.SHA256
import System.Random
import System.IO.Unsafe
import qualified Codec.Bytable as B
import Codec.Bytable.BigEndian ()

secp256r1 = getCurveByName SEC_p256r1

g = ecc_g . common_curve $ secp256r1

n = ecc_n . common_curve $ secp256r1

sk = PrivateKey secp256r1 $ unsafePerformIO getR

getR = randomRIO (1, n - 1)

mySignWith k (PrivateKey curve d) hash msg = do
	let	z = tHash hash msg n
		CurveCommon _ _ g n _ = common_curve curve
		mul = pointMul curve
	let	point = k `mul` g
	r <- case point of
		PointO -> Nothing
		Point x _ -> return $ x `mod` n
	kInv <- inverse k n
	let s = kInv * (z + r * d) `mod` n
	when (r == 0 || s == 0) Nothing
	return $ Signature r s

flp (Point x y) = Point x $ - y

blindSign bl k (PrivateKey curve d) hash msg = do
	let	CurveCommon _ _ g n _ = common_curve curve
		mul = pointMul curve
		add = pointAdd curve
		z = tHash hash msg n
		bp = bl `mul` g
		bpoint = k `mul` (g `add` bp)
		point = bpoint `add` (flp $ k `mul` bp)
	r <- case point of
		PointO -> Nothing
		Point x _ -> return $ x `mod` n
	kInv <- inverse k n
	let s = kInv * (z + r * d) `mod` n
	when (r == 0 || s == 0) Nothing
	return $ Signature r s

tHash hs m n
	| d > 0 = e `shiftR` d
	| otherwise = e
	where
	Right e = B.fromByteString $ hs m
	d = myLog2 e - myLog2 n
--	d = log2 e - log2 n

log2 :: Integer -> Int
log2 = ceiling . logBase (2 :: Double) . fromIntegral

myLog2 :: Integer -> Int
myLog2 0 = 0
myLog2 n = 1 + myLog2 (n `shiftR` 1)

check :: Integer -> Bool
check n = log2 n == myLog2 n
