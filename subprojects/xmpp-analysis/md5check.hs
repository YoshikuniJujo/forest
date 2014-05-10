{-# LANGUAGE OverloadedStrings #-}

import Crypto.Hash.MD5
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import Numeric
import Data.Word

(+++) :: ByteString -> ByteString -> ByteString
(+++) = BS.append

username, realm, qop, uri, nonce, nc, cnonce, authzid :: ByteString
username = "yoshikuni"
realm = "localhost"
password = "password"
qop = "auth"
uri = "xmpp/localhost"
nonce = "5bdc3032-7d06-49d5-986d-ede4c5b78159"
nc = "00000001"
cnonce = "00DEADBEEF00"
-- authzid = "yoshikuni@localhost/profanity"
authzid = "yoshikuni@localhost"

hash32 :: ByteString -> ByteString
hash32 = BSC.pack . concatMap hex2 . BS.unpack . hash

hex2 :: Word8 -> String
hex2 w = replicate (2 - length s) '0' ++ s
	where
	s = showHex w ""

x = username +++ ":" +++ realm +++ ":" +++ password

y = hash x

a1 = y +++ ":" +++ nonce +++ ":" +++ cnonce -- +++ ":" +++ authzid
ha1 = hash32 a1

a2 = "AUTHENTICATE:" +++ uri

ha2 = hash32 a2

kd = ha1 +++ ":" +++ nonce +++ ":" +++ nc +++ ":" +++ cnonce +++ ":" +++
	qop +++ ":" +++ ha2

z = hash32 kd

hex :: ByteString -> String
hex = concatMap (flip showHex "") . BS.unpack
