module Extension (
	ExtensionList, parseExtensionList, extensionListToByteString
) where

import Control.Applicative

import ByteStringMonad
import ToByteString

data ExtensionList
	= ExtensionListRaw ByteString
	deriving Show

parseExtensionList :: ByteStringM ExtensionList
parseExtensionList = ExtensionListRaw <$> takeLen 2

extensionListToByteString :: ExtensionList -> ByteString
extensionListToByteString (ExtensionListRaw e) = lenBodyToByteString 2 e
