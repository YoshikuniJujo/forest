module ClientHello (
	ClientHello,
	byteStringToClientHello,
	clientHelloToByteString
) where

import Data.ByteString (ByteString)

byteStringToClientHello :: ByteString -> Either String ClientHello
byteStringToClientHello bs = Right $ ClientHelloRaw bs

clientHelloToByteString :: ClientHello -> ByteString
clientHelloToByteString (ClientHelloRaw bs) = bs

data ClientHello
	= ClientHelloRaw ByteString
	deriving Show
