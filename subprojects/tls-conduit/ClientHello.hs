module ClientHello (
	ClientHello,
	parseClientHello,
	clientHelloToByteString
) where

import qualified Data.ByteString as BS

import Parts
-- import Tools

parseClientHello :: BS.ByteString -> Either String ClientHello
parseClientHello src = do
	(v, r1) <- version src
	(r, r2) <- random r1
	(sid, r3) <- sessionID r2
	(css, r4) <- list 2 cipherSuite r3
	(cms, r5) <- list 1 compressionMethod r4
	return $ ClientHello v r sid css cms r5

clientHelloToByteString :: ClientHello -> BS.ByteString
clientHelloToByteString (ClientHello v r sid css cms rest) =
	versionToByteString v `BS.append`
	randomToByteString r `BS.append`
	sessionIDToByteString sid `BS.append`
	listToByteString 2 cipherSuiteToByteString css `BS.append`
	listToByteString 1 compressionMethodToByteString cms `BS.append`
	rest
clientHelloToByteString (ClientHelloRaw bs) = bs

data ClientHello
	= ClientHello Version Random SessionID [CipherSuite] [CompressionMethod]
		BS.ByteString
	| ClientHelloRaw BS.ByteString
	deriving Show
