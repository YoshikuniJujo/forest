module EllipticCurve (EllipticCurveList, ellipticCurveList) where

import Prelude hiding (take)
import Control.Monad

import Data.Conduit
import qualified Data.Conduit.List as List
import Data.Conduit.Binary

import Data.Word
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

import Tools

ellipticCurveList :: Monad m => Conduit BS.ByteString m EllipticCurveList
ellipticCurveList = do
	len <- getLen 2
	body <- take len
	(sourceLbs body $$ ellipticCurve =$ List.consume) >>= yield

ellipticCurve :: Monad m => Conduit BS.ByteString m NamedCurve
ellipticCurve = do
	nc <- take 2
	when (LBS.length nc == 2) $ do
		yield $ namedCurve $ toWord16 nc
		ellipticCurve

type EllipticCurveList = [NamedCurve]

toWord16 :: LBS.ByteString -> Word16
toWord16 bs = let
	w1 = LBS.head bs
	w2 = LBS.head $ LBS.tail bs in
	fromIntegral w1 * 256 + fromIntegral w2

data NamedCurve
	= SECP256RL
	| SECP384RL
	| SECP521RL
	| NamedCurveOthers Word16
	deriving Show

namedCurve :: Word16 -> NamedCurve
namedCurve 23 = SECP256RL
namedCurve 24 = SECP384RL
namedCurve 25 = SECP521RL
namedCurve w = NamedCurveOthers w
