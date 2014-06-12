module NamedCurve (NamedCurve(..)) where

import Data.Bits
import Data.Word
import qualified Data.ByteString as BS
import qualified Codec.Bytable as B

data NamedCurve
	= Secp256r1
	| Secp384r1
	| Secp521r1
	| NamedCurveRaw Word16
	deriving Show

instance B.Bytable NamedCurve where
	fromByteString = byteStringToNamedCurve
	toByteString = namedCurveToByteString

byteStringToNamedCurve :: BS.ByteString -> Either String NamedCurve
byteStringToNamedCurve bs = case BS.unpack bs of
	[w1, w2] -> Right $ case fromIntegral w1 `shiftL` 8 .|. fromIntegral w2 of
		23 -> Secp256r1
		24 -> Secp384r1
		25 -> Secp521r1
		nc -> NamedCurveRaw nc
	_ -> Left "Types.byteStringToNamedCurve"

namedCurveToByteString :: NamedCurve -> BS.ByteString
namedCurveToByteString (Secp256r1) = B.toByteString (23 :: Word16)
namedCurveToByteString (Secp384r1) = B.toByteString (24 :: Word16)
namedCurveToByteString (Secp521r1) = B.toByteString (25 :: Word16)
namedCurveToByteString (NamedCurveRaw nc) = B.toByteString nc
