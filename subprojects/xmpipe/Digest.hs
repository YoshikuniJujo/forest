{-# LANGUAGE OverloadedStrings #-}

module Digest (
	DigestResponse(..),
	responseToContent,
	B64.encode,
	kvsToS,
	responseToKvs
	) where

import Control.Applicative

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64

import DigestMd5

responseToContent :: DigestResponse -> BS.ByteString
responseToContent = B64.encode . kvsToS . responseToKvs True

kvsToS :: [(BS.ByteString, BS.ByteString)] -> BS.ByteString
kvsToS [] = ""
kvsToS [(k, v)] = k `BS.append` "=" `BS.append` v
kvsToS ((k, v) : kvs) =
	k `BS.append` "=" `BS.append` v `BS.append` "," `BS.append` kvsToS kvs

responseToKvs :: Bool -> DigestResponse -> [(BS.ByteString, BS.ByteString)]
responseToKvs isClient rsp = [
	("username", quote $ drUserName rsp),
	("realm", quote $ drRealm rsp),
	("nonce", quote $ drNonce rsp),
	("cnonce", quote $ drCnonce rsp),
	("nc", drNc rsp),
	("qop", drQop rsp),
	("digest-uri", quote $ drDigestUri rsp),
	("response", calcMd5 isClient rsp),
	("charset", drCharset rsp)
	]

quote :: BS.ByteString -> BS.ByteString
quote = (`BS.append` "\"") . ("\"" `BS.append`)

data DigestResponse = DR {
	drUserName :: BS.ByteString,
	drRealm :: BS.ByteString,
	drPassword :: BS.ByteString,
	drCnonce :: BS.ByteString,
	drNonce :: BS.ByteString,
	drNc :: BS.ByteString,
	drQop :: BS.ByteString,
	drDigestUri :: BS.ByteString,
	drCharset :: BS.ByteString }
	deriving Show

calcMd5 :: Bool -> DigestResponse -> BS.ByteString
calcMd5 isClient = digestMd5 isClient
	<$> drUserName <*> drRealm <*> drPassword <*> drQop <*> drDigestUri
	<*> drNonce <*> drNc <*> drCnonce
