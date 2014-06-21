import Data.Bits
import Crypto.PubKey.ECC.Prim
import Crypto.Types.PubKey.ECC
import System.Random
import System.IO.Unsafe

add = pointAdd secp256r1
mul = pointMul secp256r1

secp256r1 = getCurveByName SEC_p256r1

rev (Point x y) = Point x (- y)

point = Point 10 85

bl = Point 32 95

bl234 = mul 234 bl

bl234rev = rev bl234

point234 = mul 234 point

pointBl = add point bl

pointBl234 = mul 234 pointBl

point234' = add pointBl234 bl234rev

g = ecc_g . common_curve $ secp256r1

n = ecc_n . common_curve $ secp256r1

qlen 0 = 0
qlen n = 1 + qlen (n `shiftR` 1)

getR = randomRIO (1, n - 1)

p = unsafePerformIO getR `mul` g

x = unsafePerformIO getR `mul` g

m = unsafePerformIO getR

mp = m `mul` p

mx = m `mul` x

px = p `add` x

mpx = m `mul` px

mp' = mpx `add` rev mx
