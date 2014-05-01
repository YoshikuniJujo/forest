{-# LANGUAGE OverloadedStrings #-}

module ServerHello (ServerHello, serverHello, serverHelloToByteString) where

import qualified Data.ByteString as BS

import Extension
import Parts
import Tools

data ServerHello
	= ServerHello Version Random SessionId CipherSuite CompressionMethod
		(Maybe [Extension])
	| ServerHelloRaw BS.ByteString
	deriving Show

serverHello :: BS.ByteString -> Either String ServerHello
serverHello src = do
	(v, r1) <- version src
	(r, r2) <- random r1
	(sid, r3) <- sessionId r2
	(cs, r4) <- cipherSuite r3
	(cm, r5) <- compressionMethod r4
	ext <- if r5 == BS.empty then return Nothing else do
		(e, r6) <- list 2 extension r5
		check "serverHello" (r6 == BS.empty)
		return $ Just e
	return $ ServerHello v r sid cs cm ext

serverHelloToByteString :: ServerHello -> BS.ByteString
serverHelloToByteString (ServerHello v r sid cs cm ext) =
	versionToByteString v `BS.append`
	randomToByteString r `BS.append`
	sessionIdToByteString sid `BS.append`
	cipherSuiteToByteString cs `BS.append`
	compressionMethodToByteString cm `BS.append`
	maybe "" (listToByteString 2 extensionToByteString) ext
serverHelloToByteString (ServerHelloRaw bs) = bs
