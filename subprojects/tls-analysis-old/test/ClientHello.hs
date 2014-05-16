{-# LANGUAGE OverloadedStrings #-}

module ClientHello (
	ClientHello,
	parseClientHello,
	clientHelloToByteString,
	takeClientRandom
) where

import qualified Data.ByteString as BS

import Extension
import Parts
import Tools
import MasterSecret

parseClientHello :: BS.ByteString -> Either String ClientHello
parseClientHello src = do
	(v, r1) <- version src
	(r, r2) <- random r1
	(sid, r3) <- sessionId r2
	(css, r4) <- list 2 cipherSuite r3
	(cms, r5) <- list 1 compressionMethod r4
	ext <- if r5 == BS.empty then return Nothing else do
		(e, r6) <- list 2 extension r5
		check "parseClientHello" (r6 == BS.empty)
		return $ Just e
	return $ ClientHello v r sid css cms ext

clientHelloToByteString :: ClientHello -> BS.ByteString
clientHelloToByteString (ClientHello v r sid css cms mext) =
	versionToByteString v `BS.append`
	randomToByteString r `BS.append`
	sessionIdToByteString sid `BS.append`
	listToByteString 2 cipherSuiteToByteString css `BS.append`
	listToByteString 1 compressionMethodToByteString cms `BS.append`
	maybe "" (listToByteString 2 extensionToByteString) mext
clientHelloToByteString (ClientHelloRaw bs) = bs

data ClientHello
	= ClientHello Version Random SessionId [CipherSuite] [CompressionMethod]
		(Maybe [Extension])
	| ClientHelloRaw BS.ByteString
	deriving Show

takeClientRandom :: ClientHello -> Maybe ClientRandom
takeClientRandom (ClientHello _ (Random r) _ _ _ _) = Just $ ClientRandom r
takeClientRandom _ = Nothing