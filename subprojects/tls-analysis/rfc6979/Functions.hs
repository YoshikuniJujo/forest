{-# LANGUAGE OverloadedStrings #-}

module Functions (
	qlen, rlen, blen,
	bits2int, int2octets, bits2octets,
	hmac, hmacSha256,
	showH, bsHex,
	initV, initK,
	initializeKV,
	createT,
	createK,
	generateK,
) where

import Data.Bits
import Numeric

import qualified Codec.Bytable as B
import qualified Data.ByteString as BS
import qualified Crypto.Hash.SHA256 as SHA256

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

hmac f bl secret msg =
    f $! BS.append opad (f $! BS.append ipad msg)
  where opad = BS.map (xor 0x5c) k'
        ipad = BS.map (xor 0x36) k'

        k' = BS.append kt pad
          where kt  = if BS.length secret > fromIntegral bl then f secret else secret
                pad = BS.replicate (fromIntegral bl - BS.length kt) 0

hmacSha256 = hmac SHA256.hash 64

showH :: (Integral i, Show i) => i -> String
showH n = replicate (length s `mod` 2) '0' ++ s
	where
	s = showHex n ""

initV :: BS.ByteString -> BS.ByteString
initV h = BS.replicate (BS.length h) 1

initK :: BS.ByteString -> BS.ByteString
initK h = BS.replicate (BS.length h) 0

bsHex :: BS.ByteString -> String
bsHex = concatMap showH . BS.unpack

-- calculateK :: Integer -> BS.ByteString -> Integer

initializeKV ::
	Integer -> Integer -> BS.ByteString -> (BS.ByteString, BS.ByteString)
initializeKV q x h = (k2, v2)
	where
	v0 = initV h
	k0 = initK h
	k1 = hmacSha256 k0 $ BS.concat
		[v0, "\x00", int2octets q x, bits2octets q h]
	v1 = hmacSha256 k1 v0
	k2 = hmacSha256 k1 $ BS.concat
		[v1, "\x01", int2octets q x, bits2octets q h]
	v2 = hmacSha256 k2 v1

createT :: Integer -> BS.ByteString -> BS.ByteString ->
	BS.ByteString -> (BS.ByteString, BS.ByteString)
createT q k v t
	| blen t < qlen q = createT q k v' $ t `BS.append` v'
	| otherwise = (t, v)
	where
	v' = hmacSha256 k v

createK :: Integer -> BS.ByteString -> BS.ByteString -> Integer
createK q k v
	| 0 < kk && kk < q = kk
	| otherwise = createK q k' v''
	where
	(t, v') = createT q k v ""
	kk = bits2int q t
	k' = hmacSha256 k $ v' `BS.append` "\x00"
	v'' = hmacSha256 k' v'

generateK :: Integer -> Integer -> BS.ByteString -> Integer
generateK q x m = createK q k v
	where
	h = SHA256.hash m
	(k, v) = initializeKV q x h
