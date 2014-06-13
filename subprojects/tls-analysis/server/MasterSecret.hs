{-# LANGUAGE OverloadedStrings #-}
module MasterSecret (
	tupleToVersion,
	ClientRandom(..), ServerRandom(..),
	generateMasterSecret,
	generateKeyBlock,
	generateFinished, MSVersion(..),

	hmac,
) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.MD5 as MD5

import qualified Crypto.Hash.SHA256 as SHA256
import Data.Bits (xor)
import Data.Word

tupleToVersion :: (Word8, Word8) -> Maybe MSVersion
tupleToVersion (3, 1) = Just TLS10
tupleToVersion (3, 3) = Just TLS12
tupleToVersion _ = Nothing

type Bytes = ByteString

type PRF = Bytes -> Bytes -> Int -> Bytes

data ClientRandom = ClientRandom B.ByteString deriving Show
data ServerRandom = ServerRandom B.ByteString deriving Show

generateMasterSecretTls :: PRF -> Bytes -> ClientRandom -> ServerRandom -> Bytes
generateMasterSecretTls prf premasterSecret (ClientRandom c) (ServerRandom s) =
    prf premasterSecret seed 48
  where seed = B.concat [ "master secret", c, s ]

generateFinished :: MSVersion -> Bool -> Bytes -> Bytes -> Bytes
generateFinished TLS10 isC ms hash =
	prfMd5Sha1 ms (getFinishedLabel isC `B.append` hash) 12
generateFinished TLS12 isC ms hash =
	prfSha256 ms (getFinishedLabel isC `B.append` hash) 12
generateFinished _ _ _ _ = error "Not implemented"

getFinishedLabel :: Bool -> B.ByteString
getFinishedLabel True = "client finished"
getFinishedLabel False = "server finished"

generateMasterSecret :: Bytes -> ClientRandom -> ServerRandom -> Bytes
generateMasterSecret = generateMasterSecretTls prfSha256

generateKeyBlockTls :: PRF -> ClientRandom -> ServerRandom -> Bytes -> Int -> Bytes
generateKeyBlockTls prf (ClientRandom c) (ServerRandom s) mastersecret =
    prf mastersecret seed
    where seed = B.concat [ "key expansion", s, c ]

data MSVersion = SSL2 | SSL3 | TLS10 | TLS11 | TLS12
	deriving (Eq, Show)

generateKeyBlock :: ClientRandom -> ServerRandom -> Bytes -> Int -> Bytes
generateKeyBlock = generateKeyBlockTls prfSha256

type HMAC = ByteString -> ByteString -> ByteString

hmac :: (ByteString -> ByteString) -> Int -> HMAC
hmac f bl secret msg =
    f $! B.append opad (f $! B.append ipad msg)
  where opad = B.map (xor 0x5c) k'
        ipad = B.map (xor 0x36) k'

        k' = B.append kt pad
          where kt  = if B.length secret > fromIntegral bl then f secret else secret
                pad = B.replicate (fromIntegral bl - B.length kt) 0

hmacMD5 :: HMAC
hmacMD5 = hmac MD5.hash 64

hmacSHA1 :: HMAC
hmacSHA1 = hmac SHA1.hash 64

hmacSHA256 :: HMAC
hmacSHA256 = hmac SHA256.hash 64

hmacIter :: HMAC -> ByteString -> ByteString -> ByteString -> Int -> [ByteString]
hmacIter f secret seed aprev len =
    let an = f secret aprev in
    let out = f secret (B.concat [an, seed]) in
    let digestsize = fromIntegral $ B.length out in
    if digestsize >= len
        then [ B.take (fromIntegral len) out ]
        else out : hmacIter f secret seed an (len - digestsize)

prfSha1 :: ByteString -> ByteString -> Int -> ByteString
prfSha1 secret seed len = B.concat $ hmacIter hmacSHA1 secret seed seed len

prfMd5 :: ByteString -> ByteString -> Int -> ByteString
prfMd5 secret seed len = B.concat $ hmacIter hmacMD5 secret seed seed len

prfMd5Sha1 :: ByteString -> ByteString -> Int -> ByteString
prfMd5Sha1 secret seed len =
    B.pack $ B.zipWith xor (prfMd5 s1 seed len) (prfSha1 s2 seed len)
  where slen  = B.length secret
        s1    = B.take (slen `div` 2 + slen `mod` 2) secret
        s2    = B.drop (slen `div` 2) secret

prfSha256 :: ByteString -> ByteString -> Int -> ByteString
prfSha256 secret seed len = B.concat $ hmacIter hmacSHA256 secret seed seed len
