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
	ClientRandom(..), ServerRandom(..),
	masterSecret, keyBlock,
	generateFinished
) where

import MAC
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC

import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.MD5 as MD5

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

generateFinished :: Bytes -> Bytes -> Bytes
generateFinished ms hash = prfMd5Sha1 ms ("client finished" `B.append` hash) 12

masterSecret :: B.ByteString -> ClientRandom -> ServerRandom -> B.ByteString
masterSecret = generateMasterSecret TLS10

generateMasterSecret :: Version -> Bytes -> ClientRandom -> ServerRandom -> Bytes
generateMasterSecret SSL2  = generateMasterSecretSsl
generateMasterSecret SSL3  = generateMasterSecretSsl
generateMasterSecret TLS10 = generateMasterSecretTls prfMd5Sha1
generateMasterSecret TLS11 = generateMasterSecretTls prfMd5Sha1
generateMasterSecret TLS12 = generateMasterSecretTls prfSha256

generateKeyBlockTls :: PRF -> ClientRandom -> ServerRandom -> Bytes -> Int -> Bytes
generateKeyBlockTls prf (ClientRandom c) (ServerRandom s) mastersecret =
    prf mastersecret seed where seed = B.concat [ "key expansion", s, c ]

generateKeyBlockSsl :: ClientRandom -> ServerRandom -> Bytes -> Int -> Bytes
generateKeyBlockSsl (ClientRandom c) (ServerRandom s) mastersecret kbsize =
    B.concat . map computeMD5 $ take ((kbsize `div` 16) + 1) labels
  where labels            = [ uncurry BC.replicate x | x <- zip [1..] ['A'..'Z'] ]
        computeMD5  label = MD5.hash $ B.concat [ mastersecret, computeSHA1 label ]
        computeSHA1 label = SHA1.hash $ B.concat [ label, mastersecret, s, c ]

data Version = SSL2 | SSL3 | TLS10 | TLS11 | TLS12
	deriving (Eq, Show)

keyBlock :: ClientRandom -> ServerRandom -> B.ByteString -> Int -> B.ByteString
keyBlock = generateKeyBlock TLS10

generateKeyBlock :: Version -> ClientRandom -> ServerRandom -> Bytes -> Int -> Bytes
generateKeyBlock SSL2  = generateKeyBlockSsl
generateKeyBlock SSL3  = generateKeyBlockSsl
generateKeyBlock TLS10 = generateKeyBlockTls prfMd5Sha1
generateKeyBlock TLS11 = generateKeyBlockTls prfMd5Sha1
generateKeyBlock TLS12 = generateKeyBlockTls prfSha256
