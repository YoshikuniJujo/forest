module PreMasterSecret (
	EncryptedPreMasterSecret(..),
	parseEncryptedPreMasterSecret,
	encryptedPreMasterSecretToByteString
) where

import Control.Applicative

import ByteStringMonad
import ToByteString

data EncryptedPreMasterSecret
	= EncryptedPreMasterSecret ByteString
	deriving Show

parseEncryptedPreMasterSecret :: ByteStringM EncryptedPreMasterSecret
parseEncryptedPreMasterSecret = EncryptedPreMasterSecret <$> takeLen 2

encryptedPreMasterSecretToByteString :: EncryptedPreMasterSecret -> ByteString
encryptedPreMasterSecretToByteString (EncryptedPreMasterSecret epms) =
	lenBodyToByteString 2 epms
