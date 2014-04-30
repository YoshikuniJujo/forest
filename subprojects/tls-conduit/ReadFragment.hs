module ReadFragment (
	readFragment, fragmentToByteString,
	takeHandshake
) where

import Control.Applicative

import Data.Word
import Data.Bits
import Data.ByteString (hGet)
import qualified Data.ByteString as BS

import System.IO

import Handshake

readFragment :: Handle -> IO Fragment
readFragment h = do
	ctvl <- hGet h 5
	let	[ct, vmjr, vmnr, l1, l2] = BS.unpack ctvl
	fragment (contentType ct) (version vmjr vmnr) <$>
		hGet h (fromIntegral l1 `shift` 8 .|. fromIntegral l2)

lengthToByteString :: Int -> BS.ByteString
lengthToByteString l = BS.pack
	[fromIntegral $ l `shiftR` 8, fromIntegral $ l .&. 0xff]

data ContentType
	= ContentTypeHandshake
	| ContentTypeOthers Word8
	deriving Show

contentType :: Word8 -> ContentType
contentType 22 = ContentTypeHandshake
contentType w = ContentTypeOthers w

contentTypeToByteString :: ContentType -> BS.ByteString
contentTypeToByteString ContentTypeHandshake = BS.pack [22]
contentTypeToByteString (ContentTypeOthers w) = BS.pack [w]

data Version
	= Version Word8 Word8
	deriving Show

versionToByteString :: Version -> BS.ByteString
versionToByteString (Version w1 w2) = BS.pack [w1, w2]

version :: Word8 -> Word8 -> Version
version = Version

data Fragment
	= ContentHandshake Version BS.ByteString
	| Fragment ContentType Version BS.ByteString
	deriving Show

fragment :: ContentType -> Version -> BS.ByteString -> Fragment
fragment ContentTypeHandshake v body = ContentHandshake v body
fragment ct v body = Fragment ct v body

fragmentToByteString :: Fragment -> BS.ByteString
fragmentToByteString (ContentHandshake v cnt) =
	fragmentToByteString (Fragment ContentTypeHandshake v cnt)
fragmentToByteString (Fragment ct v cnt) = contentTypeToByteString ct
	`BS.append` versionToByteString v
	`BS.append` lengthToByteString (BS.length cnt)
	`BS.append` cnt

takeHandshake :: Fragment -> Maybe [Handshake]
takeHandshake (ContentHandshake _ body) = parseHandshakeAll body
takeHandshake _ = Nothing
