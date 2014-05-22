{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      : Network.TLS.Packet
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- the Packet module contains everything necessary to serialize and deserialize things
-- with only explicit parameters, no TLS state is involved here.
--
module MasterSecret (
	versionToVersion,
	ClientRandom(..), ServerRandom(..),
	generateMasterSecret, masterSecret, keyBlock,
	generateKeyBlock,
	generateFinished, MSVersion(..),

	P.Version(..), P.versionToByteString, P.byteStringToVersion,
	P.ContentType(..), P.contentTypeToByteString, P.byteStringToContentType,

	P.Fragment(..), P.Random(..), P.CipherSuite(..),

--	P.Random(..),
--	P.CipherSuite(..),
--	P.contentTypeToByteString,
--	P.ContentType(..),
--	P.byteStringToVersion,

--	P.Version(..),
--	P.versionToByteString,
--	P.byteStringToContentType,
--	P.Version(..),

	hmac,

--	P.list1, P.whole, P.ByteStringM, P.evalByteStringM, P.headBS,

--	P.word64ToByteString, P.lenBodyToByteString,

--	P.byteStringToInt, P.intToByteString, P.showKeySingle, P.showKey,
) where

-- import MAC
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC

import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.MD5 as MD5

-- import qualified Basic as P (Version(..))
import qualified Types as P

-- import qualified Crypto.Hash.MD5 as MD5
-- import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA256 as SHA256
-- import qualified Data.ByteString as B
-- import Data.ByteString (ByteString)
import Data.Bits (xor)

versionToVersion :: P.Version -> Maybe MSVersion
versionToVersion (P.Version 3 1) = Just TLS10
versionToVersion (P.Version 3 3) = Just TLS12
versionToVersion _ = Nothing

type Bytes = ByteString

type PRF = Bytes -> Bytes -> Int -> Bytes

generateMasterSecretSsl :: Bytes -> ClientRandom -> ServerRandom -> Bytes
generateMasterSecretSsl premasterSecret (ClientRandom c) (ServerRandom s) =
    B.concat $ map computeMD5 ["A","BB","CCC"]
  where computeMD5  label = MD5.hash $ B.concat [ premasterSecret, computeSHA1 label ]
        computeSHA1 label = SHA1.hash $ B.concat [ label, premasterSecret, c, s ]

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

masterSecret :: B.ByteString -> ClientRandom -> ServerRandom -> B.ByteString
masterSecret = generateMasterSecret TLS10

generateMasterSecret :: MSVersion -> Bytes -> ClientRandom -> ServerRandom -> Bytes
generateMasterSecret SSL2  = generateMasterSecretSsl
generateMasterSecret SSL3  = generateMasterSecretSsl
generateMasterSecret TLS10 = generateMasterSecretTls prfMd5Sha1
generateMasterSecret TLS11 = generateMasterSecretTls prfMd5Sha1
generateMasterSecret TLS12 = generateMasterSecretTls prfSha256

generateKeyBlockTls :: PRF -> ClientRandom -> ServerRandom -> Bytes -> Int -> Bytes
generateKeyBlockTls prf (ClientRandom c) (ServerRandom s) mastersecret =
    prf mastersecret seed
    where seed = B.concat [ "key expansion", s, c ]

generateKeyBlockSsl :: ClientRandom -> ServerRandom -> Bytes -> Int -> Bytes
generateKeyBlockSsl (ClientRandom c) (ServerRandom s) mastersecret kbsize =
    B.concat . map computeMD5 $ take ((kbsize `div` 16) + 1) labels
  where labels            = [ uncurry BC.replicate x | x <- zip [1..] ['A'..'Z'] ]
        computeMD5  label = MD5.hash $ B.concat [ mastersecret, computeSHA1 label ]
        computeSHA1 label = SHA1.hash $ B.concat [ label, mastersecret, s, c ]

data MSVersion = SSL2 | SSL3 | TLS10 | TLS11 | TLS12
	deriving (Eq, Show)

keyBlock :: ClientRandom -> ServerRandom -> B.ByteString -> Int -> B.ByteString
keyBlock = generateKeyBlock TLS10

generateKeyBlock :: MSVersion -> ClientRandom -> ServerRandom -> Bytes -> Int -> Bytes
generateKeyBlock SSL2  = generateKeyBlockSsl
generateKeyBlock SSL3  = generateKeyBlockSsl
generateKeyBlock TLS10 = generateKeyBlockTls prfMd5Sha1
generateKeyBlock TLS11 = generateKeyBlockTls prfMd5Sha1
generateKeyBlock TLS12 = generateKeyBlockTls prfSha256

type HMAC = ByteString -> ByteString -> ByteString

{-
macSSL :: (ByteString -> ByteString) -> HMAC
macSSL f secret msg = f $! B.concat [ secret, B.replicate padlen 0x5c,
                        f $! B.concat [ secret, B.replicate padlen 0x36, msg ] ]
  where -- get the type of algorithm out of the digest length by using the hash fct.
        padlen = if B.length (f B.empty) == 16 then 48 else 40
	-}

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
