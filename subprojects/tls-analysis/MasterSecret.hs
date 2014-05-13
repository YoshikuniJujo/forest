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

	P.ProtocolVersion(..),

--	P.Random(..),
--	P.CipherSuite(..),
--	P.contentTypeToByteString,
--	P.ContentType(..),
--	P.byteStringToVersion,

--	P.ProtocolVersion(..),
--	P.versionToByteString,
--	P.byteStringToContentType,
--	P.Version(..),

	hmac,

--	P.list1, P.whole, P.ByteStringM, P.evalByteStringM, P.headBS,

--	P.word64ToByteString, P.lenBodyToByteString,

--	P.byteStringToInt, P.intToByteString, P.showKeySingle, P.showKey,
) where

import MAC
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC

import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.MD5 as MD5

import qualified Types as P (ProtocolVersion(..))

versionToVersion :: P.ProtocolVersion -> Maybe MSVersion
versionToVersion (P.ProtocolVersion 3 1) = Just TLS10
versionToVersion (P.ProtocolVersion 3 3) = Just TLS12
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
