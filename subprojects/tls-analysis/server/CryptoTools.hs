{-# LANGUAGE OverloadedStrings, PackageImports, TupleSections #-}

module CryptoTools (
	encrypt, decrypt, hashSha1, hashSha256,

	MSVersion(..), tupleToVersion,
	ClientRandom(..), ServerRandom(..),

	makeKeys, finishedHash_,
) where

import Data.Bits

import Data.Word
import qualified Data.ByteString as BS
import "crypto-random" Crypto.Random
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA256 as SHA256
import Crypto.Cipher.AES

import qualified Codec.Bytable as B
import Codec.Bytable.BigEndian ()

type Hash = (BS.ByteString -> BS.ByteString, Int)

hashSha1, hashSha256 :: Hash
hashSha1 = (SHA1.hash, 20)
hashSha256 = (SHA256.hash, 32)

encrypt :: CPRG gen =>
	Hash -> BS.ByteString -> BS.ByteString -> Word64 ->
	BS.ByteString -> BS.ByteString -> gen -> (BS.ByteString, gen)
encrypt (hs, _) key mk sn pre msg gen = 
	encrypt_ gen key . padd $ msg `BS.append` mac
	where
	mac = calcMac hs sn mk $ BS.concat
		[pre, B.addLen (undefined :: Word16) msg]

calcMac :: (BS.ByteString -> BS.ByteString) ->
	Word64 -> BS.ByteString -> BS.ByteString -> BS.ByteString
calcMac hs sn mk inp =
	hmac hs 64 mk $ B.encode sn `BS.append` inp

padd :: BS.ByteString -> BS.ByteString
padd bs = bs `BS.append` pd
	where
	plen = 16 - (BS.length bs + 1) `mod` 16
	pd = BS.replicate (plen + 1) $ fromIntegral plen

encrypt_ :: CPRG gen =>
	gen -> BS.ByteString -> BS.ByteString -> (BS.ByteString, gen)
encrypt_ gen key pln = let
	(iv, gen') = cprgGenerate 16 gen in
	(iv `BS.append` encryptCBC (initAES key) iv pln, gen')

unpadd :: BS.ByteString -> BS.ByteString
unpadd bs = BS.take (BS.length bs - plen) bs
	where
	plen = fromIntegral (myLast "unpadd" bs) + 1

myLast :: String -> BS.ByteString -> Word8
myLast msg "" = error msg
myLast _ bs = BS.last bs

decrypt_ :: BS.ByteString -> BS.ByteString -> BS.ByteString
decrypt_ key ivenc = let
	(iv, enc) = BS.splitAt 16 ivenc in
	decryptCBC (initAES key) iv enc

makeKeys :: Int -> BS.ByteString -> BS.ByteString ->
	BS.ByteString -> Either String
	(BS.ByteString, BS.ByteString, BS.ByteString, BS.ByteString, BS.ByteString)
makeKeys kl cr sr pms = do
	let	ms = generateMasterSecret pms cr sr
		ems = generateKeyBlock
			(ClientRandom cr) (ServerRandom sr) ms $ kl * 2 + 32
		[cwmk, swmk, cwk, swk] = divide [kl, kl, 16, 16] ems
	return (ms, cwmk, swmk, cwk, swk)
	where
	divide [] _ = []
	divide (n : ns) bs
		| bs == BS.empty = []
		| otherwise = let (x, xs) = BS.splitAt n bs in x : divide ns xs

finishedHash_ :: Bool -> BS.ByteString -> BS.ByteString -> BS.ByteString
finishedHash_ = generateFinished TLS12

generateFinished :: MSVersion -> Bool -> Bytes -> Bytes -> Bytes
generateFinished TLS12 isC ms hash =
	prfSha256 ms (getFinishedLabel isC `BS.append` hash) 12
generateFinished _ _ _ _ = error "Not implemented"

getFinishedLabel :: Bool -> BS.ByteString
getFinishedLabel True = "client finished"
getFinishedLabel False = "server finished"

decrypt :: Hash ->
	BS.ByteString -> BS.ByteString -> Word64 ->
	BS.ByteString -> BS.ByteString -> Either String BS.ByteString
decrypt (hs, ml) key mk sn pre enc = if mac == cmac then Right body else
	Left $ "CryptoTools.decrypt: bad MAC:\n\t" ++
		"Expected: " ++ show cmac ++ "\n\t" ++
		"Recieved: " ++ show mac ++ "\n\t" ++
		"ml: " ++ show ml ++ "\n"
	where
	bm = unpadd $ decrypt_ key enc
	(body, mac) = BS.splitAt (BS.length bm - ml) bm
	cmac = calcMac hs sn mk $ BS.concat
		[pre, B.addLen (undefined :: Word16) body]

tupleToVersion :: (Word8, Word8) -> Maybe MSVersion
tupleToVersion (3, 1) = Just TLS10
tupleToVersion (3, 3) = Just TLS12
tupleToVersion _ = Nothing

type Bytes = BS.ByteString

type PRF = Bytes -> Bytes -> Int -> Bytes

data ClientRandom = ClientRandom BS.ByteString deriving Show
data ServerRandom = ServerRandom BS.ByteString deriving Show

generateMasterSecret :: Bytes -> BS.ByteString -> BS.ByteString -> Bytes
generateMasterSecret pms c s = prfSha256 pms (BS.concat ["master secret", c, s]) 48

generateKeyBlockTls :: PRF -> ClientRandom -> ServerRandom -> Bytes -> Int -> Bytes
generateKeyBlockTls prf (ClientRandom c) (ServerRandom s) mastersecret =
    prf mastersecret seed
    where seed = BS.concat [ "key expansion", s, c ]

data MSVersion = SSL2 | SSL3 | TLS10 | TLS11 | TLS12
	deriving (Eq, Show)

generateKeyBlock :: ClientRandom -> ServerRandom -> Bytes -> Int -> Bytes
generateKeyBlock = generateKeyBlockTls prfSha256

type HMAC = BS.ByteString -> BS.ByteString -> BS.ByteString

hmac :: (BS.ByteString -> BS.ByteString) -> Int -> HMAC
hmac f bl secret msg =
    f $! BS.append opad (f $! BS.append ipad msg)
  where opad = BS.map (xor 0x5c) k'
        ipad = BS.map (xor 0x36) k'

        k' = BS.append kt pad
          where kt  = if BS.length secret > fromIntegral bl then f secret else secret
                pad = BS.replicate (fromIntegral bl - BS.length kt) 0

hmacSHA256 :: HMAC
hmacSHA256 = hmac SHA256.hash 64

hmacIter :: HMAC -> BS.ByteString -> BS.ByteString -> BS.ByteString -> Int -> [BS.ByteString]
hmacIter f secret seed aprev len =
    let an = f secret aprev in
    let out = f secret (BS.concat [an, seed]) in
    let digestsize = fromIntegral $ BS.length out in
    if digestsize >= len
        then [ BS.take (fromIntegral len) out ]
        else out : hmacIter f secret seed an (len - digestsize)

prfSha256 :: BS.ByteString -> BS.ByteString -> Int -> BS.ByteString
prfSha256 secret seed len = BS.concat $ hmacIter hmacSHA256 secret seed seed len
