{-# LANGUAGE OverloadedStrings #-}

module Rfc6979 (generateK) where

import Data.Bits
import Numeric

import qualified Codec.Bytable as B
import qualified Codec.Bytable.BigEndian()
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

initializeKV :: Hash ->
	Integer -> Integer -> BS.ByteString -> (BS.ByteString, BS.ByteString)
initializeKV hsbl@(hs, bl) q x h = (k2, v2)
	where
	v0 = initV h
	k0 = initK h
	k1 = hmac hs bl k0 $ BS.concat
		[v0, "\x00", int2octets q x, bits2octets q h]
	v1 = hmac hs bl k1 v0
	k2 = hmac hs bl k1 $ BS.concat
		[v1, "\x01", int2octets q x, bits2octets q h]
	v2 = hmac hs bl k2 v1

createT :: Hash -> Integer -> BS.ByteString -> BS.ByteString ->
	BS.ByteString -> (BS.ByteString, BS.ByteString)
createT hsbl@(hs, bl) q k v t
	| blen t < qlen q = createT hsbl q k v' $ t `BS.append` v'
	| otherwise = (t, v)
	where
	v' = hmac hs bl k v

createK :: Hash -> Integer -> BS.ByteString -> BS.ByteString -> Integer
createK hsbl@(hs, bl) q k v
	| 0 < kk && kk < q = kk
	| otherwise = createK hsbl q k' v''
	where
	(t, v') = createT hsbl q k v ""
	kk = bits2int q t
	k' = hmac hs bl k $ v' `BS.append` "\x00"
	v'' = hmac hs bl k' v'

generateK :: Hash -> Integer -> Integer -> BS.ByteString -> Integer
generateK hsbl@(hs, _) q x m = createK hsbl q k v
	where
	h = hs m
	(k, v) = initializeKV hsbl q x h

type Hash = (BS.ByteString -> BS.ByteString, Int)
