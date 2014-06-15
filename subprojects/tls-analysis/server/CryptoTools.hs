{-# LANGUAGE OverloadedStrings, PackageImports, TupleSections #-}

module CryptoTools (
	encryptMessage, decryptMessage, hashSha1, hashSha256,

	MSVersion(..),
	tupleToVersion,
	ClientRandom(..), ServerRandom(..),
	generateMasterSecret, generateKeyBlock, generateFinished,

	generateKeys_,
	finishedHash_,
) where

import Data.Bits

import Data.Word
import qualified Data.ByteString as BS
import "crypto-random" Crypto.Random
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Hash.MD5 as MD5
import Crypto.Cipher.AES

import qualified Codec.Bytable as B
import Codec.Bytable.BigEndian ()

type Hash = (BS.ByteString -> BS.ByteString, Int)

hashSha1, hashSha256 :: Hash
hashSha1 = (SHA1.hash, 20)
hashSha256 = (SHA256.hash, 32)

encryptMessage :: CPRG gen =>
	Hash -> BS.ByteString -> BS.ByteString -> Word64 ->
	BS.ByteString -> BS.ByteString -> gen -> (BS.ByteString, gen)
encryptMessage (hs, _) key mk sn pre msg gen = 
	encrypt gen key . padd $ msg `BS.append` mac
	where
	mac = calcMac hs sn mk $ BS.concat
		[pre, B.addLength (undefined :: Word16) msg]

calcMac :: (BS.ByteString -> BS.ByteString) ->
	Word64 -> BS.ByteString -> BS.ByteString -> BS.ByteString
calcMac hs sn mk inp =
	hmac hs 64 mk $ B.toByteString sn `BS.append` inp

padd :: BS.ByteString -> BS.ByteString
padd bs = bs `BS.append` pd
	where
	plen = 16 - (BS.length bs + 1) `mod` 16
	pd = BS.replicate (plen + 1) $ fromIntegral plen

encrypt :: CPRG gen =>
	gen -> BS.ByteString -> BS.ByteString -> (BS.ByteString, gen)
encrypt gen key pln = let
	(iv, gen') = cprgGenerate 16 gen in
	(iv `BS.append` encryptCBC (initAES key) iv pln, gen')

unpadd :: BS.ByteString -> BS.ByteString
unpadd bs = BS.take (BS.length bs - plen) bs
	where
	plen = fromIntegral (myLast "unpadd" bs) + 1

myLast :: String -> BS.ByteString -> Word8
myLast msg "" = error msg
myLast _ bs = BS.last bs

decrypt :: BS.ByteString -> BS.ByteString -> BS.ByteString
decrypt key ivenc = let
	(iv, enc) = BS.splitAt 16 ivenc in
	decryptCBC (initAES key) iv enc

generateKeys_ :: Int -> BS.ByteString -> BS.ByteString ->
	BS.ByteString -> Either String
	(BS.ByteString, BS.ByteString, BS.ByteString, BS.ByteString, BS.ByteString)
generateKeys_ kl cr sr pms = do
	let	ms = generateMasterSecret
			pms (ClientRandom cr) (ServerRandom sr)
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

decryptMessage :: Hash ->
	BS.ByteString -> BS.ByteString -> Word64 ->
	BS.ByteString -> BS.ByteString -> Either String BS.ByteString
decryptMessage (hs, ml) key mk sn pre enc = if mac == cmac then Right body else
	Left $ "CryptoTools.decryptMessage: bad MAC:\n\t" ++
		"Expected: " ++ show cmac ++ "\n\t" ++
		"Recieved: " ++ show mac ++ "\n\t" ++
		"ml: " ++ show ml ++ "\n"
	where
	bm = unpadd $ decrypt key enc
	(body, mac) = BS.splitAt (BS.length bm - ml) bm
	cmac = calcMac hs sn mk $ BS.concat
		[pre, B.addLength (undefined :: Word16) body]

tupleToVersion :: (Word8, Word8) -> Maybe MSVersion
tupleToVersion (3, 1) = Just TLS10
tupleToVersion (3, 3) = Just TLS12
tupleToVersion _ = Nothing

type Bytes = BS.ByteString

type PRF = Bytes -> Bytes -> Int -> Bytes

data ClientRandom = ClientRandom BS.ByteString deriving Show
data ServerRandom = ServerRandom BS.ByteString deriving Show

generateMasterSecretTls :: PRF -> Bytes -> ClientRandom -> ServerRandom -> Bytes
generateMasterSecretTls prf premasterSecret (ClientRandom c) (ServerRandom s) =
    prf premasterSecret seed 48
  where seed = BS.concat [ "master secret", c, s ]

generateFinished :: MSVersion -> Bool -> Bytes -> Bytes -> Bytes
generateFinished TLS10 isC ms hash =
	prfMd5Sha1 ms (getFinishedLabel isC `BS.append` hash) 12
generateFinished TLS12 isC ms hash =
	prfSha256 ms (getFinishedLabel isC `BS.append` hash) 12
generateFinished _ _ _ _ = error "Not implemented"

getFinishedLabel :: Bool -> BS.ByteString
getFinishedLabel True = "client finished"
getFinishedLabel False = "server finished"

generateMasterSecret :: Bytes -> ClientRandom -> ServerRandom -> Bytes
generateMasterSecret = generateMasterSecretTls prfSha256

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

hmacMD5 :: HMAC
hmacMD5 = hmac MD5.hash 64

hmacSHA1 :: HMAC
hmacSHA1 = hmac SHA1.hash 64

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

prfSha1 :: BS.ByteString -> BS.ByteString -> Int -> BS.ByteString
prfSha1 secret seed len = BS.concat $ hmacIter hmacSHA1 secret seed seed len

prfMd5 :: BS.ByteString -> BS.ByteString -> Int -> BS.ByteString
prfMd5 secret seed len = BS.concat $ hmacIter hmacMD5 secret seed seed len

prfMd5Sha1 :: BS.ByteString -> BS.ByteString -> Int -> BS.ByteString
prfMd5Sha1 secret seed len =
    BS.pack $ BS.zipWith xor (prfMd5 s1 seed len) (prfSha1 s2 seed len)
  where slen  = BS.length secret
        s1    = BS.take (slen `div` 2 + slen `mod` 2) secret
        s2    = BS.drop (slen `div` 2) secret

prfSha256 :: BS.ByteString -> BS.ByteString -> Int -> BS.ByteString
prfSha256 secret seed len = BS.concat $ hmacIter hmacSHA256 secret seed seed len
