import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.Types.PubKey.ECC as ECC
import qualified Crypto.Hash.SHA256 as SHA256
import Numeric
import qualified Data.ByteString as BS
import qualified Codec.Bytable as B
import Codec.Bytable.BigEndian()
import Data.Maybe
import Data.Bits
import Crypto.Number.ModArithmetic

import Functions

q = 0x04000000000000000000020108a2e0cc0d99f8a5ef

m = 0x0800000000000000000000000000000000000000c9
a = 1
b = 1
g = ECC.Point gx gy
gx = 0x02fe13c0537bbc11acaa07d793de4e6d5e5c94eee8
gy = 0x0289070fb05d38ff58321f2e800536d538ccdaa3d9
n = q
h = 2

sect163k1 :: ECC.Curve
sect163k1 = ECC.CurveF2m $ ECC.CurveBinary m $ ECC.CurveCommon a b g n h

x :: Integer
x = 0x09a4d6792295a7f730fc3f2b49cbc0f62e862272f

v0, k0 :: Integer
v0 = 0x0101010101010101010101010101010101010101010101010101010101010101
k0 = 0x0000000000000000000000000000000000000000000000000000000000000000

h1 :: BS.ByteString
h1 = SHA256.hash "sample"

byteStringToInteger :: BS.ByteString -> Integer
byteStringToInteger = either error id . B.fromByteString

hh = byteStringToInteger h1 `shiftR` (256 - 163)

b2oh1 :: BS.ByteString
b2oh1 = B.toByteString $ byteStringToInteger h1 `shiftR` (256 - 163) `mod` q

k1 = hmacSha256 (B.toByteString k0) $ BS.concat [
	B.toByteString v0,
	"\x00",
	"\x00", B.toByteString x,
	b2oh1 ]

v1 = hmacSha256 k1 $ B.toByteString v0

k2 = hmacSha256 k1 $ BS.concat [ v1, "\x01", "\x00", B.toByteString x, b2oh1 ]

v2 = hmacSha256 k2 v1

v3 = hmacSha256 k2 v2

t1 = byteStringToInteger v3

kk1 = t1 `shiftR` (256 - 163)

k3 = hmacSha256 k2 $ v3 `BS.append` "\x00"

v4 = hmacSha256 k3 v3

v5 = hmacSha256 k3 v4

t2 = byteStringToInteger v5

kk2 = t2 `shiftR` (256 - 163)

k4 = hmacSha256 k3 $ v5 `BS.append` "\x00"

v6 = hmacSha256 k4 v5

v7 = hmacSha256 k4 v6

t3 = byteStringToInteger v7

kk3 = t3 `shiftR` (256 - 163)

r = let ECC.Point x _ = ECC.pointMul sect163k1 kk3 g in x `mod` q

s = (hh + x * r) * fromJust (inverse kk3 q) `mod` q
