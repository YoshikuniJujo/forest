module Parts (
	Version, version, versionToByteString,
	ContentType(..), contentType, contentTypeToByteString
) where

import Data.Word
import qualified Data.ByteString as BS

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
