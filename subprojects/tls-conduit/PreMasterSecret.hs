module PreMasterSecret (
	EncryptedPreMasterSecret(..),
	parseEncryptedPreMasterSecret,
	encryptedPreMasterSecretToByteString
) where

import Numeric

import Control.Applicative

import ByteStringMonad
import ToByteString

data EncryptedPreMasterSecret
	= EncryptedPreMasterSecret ByteString

instance Show EncryptedPreMasterSecret where
	show (EncryptedPreMasterSecret epms) = "(EncryptedPreMasterSecret " ++
		showKey epms ++ ")"

showKey :: ByteString -> String
showKey = concatMap showH . unpack

showH :: Word8 -> String
showH w = replicate (2 - length s) '0' ++ s
	where
	s = showHex w ""

parseEncryptedPreMasterSecret :: ByteStringM EncryptedPreMasterSecret
parseEncryptedPreMasterSecret = EncryptedPreMasterSecret <$> takeLen 2

encryptedPreMasterSecretToByteString :: EncryptedPreMasterSecret -> ByteString
encryptedPreMasterSecretToByteString (EncryptedPreMasterSecret epms) =
	lenBodyToByteString 2 epms
