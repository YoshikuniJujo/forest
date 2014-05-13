module PreMasterSecret (
	EncryptedPreMasterSecret(..),
	parseEncryptedPreMasterSecret,
	encryptedPreMasterSecretToByteString,

	ByteStringM, section, emptyBS, throwError, whole, append,
	lenBodyToByteString, headBS,
) where

import Numeric

import Control.Applicative

import ByteStringMonad
-- import ToByteString

data EncryptedPreMasterSecret
	= EncryptedPreMasterSecret { getEncryptedPreMasterSecret :: ByteString }

instance Show EncryptedPreMasterSecret where
	show (EncryptedPreMasterSecret epms) = "(EncryptedPreMasterSecret " ++
		showKeyPMS epms ++ ")"

showKeyPMS :: ByteString -> String
showKeyPMS = concatMap showH . unpack

showH :: Word8 -> String
showH w = replicate (2 - length s) '0' ++ s
	where
	s = showHex w ""

parseEncryptedPreMasterSecret :: ByteStringM EncryptedPreMasterSecret
parseEncryptedPreMasterSecret = EncryptedPreMasterSecret <$> takeLen 2

encryptedPreMasterSecretToByteString :: EncryptedPreMasterSecret -> ByteString
encryptedPreMasterSecretToByteString (EncryptedPreMasterSecret epms) =
	lenBodyToByteString 2 epms
