{-# LANGUAGE TupleSections, OverloadedStrings #-}

module PreMasterSecret (
	EncryptedPreMasterSecret, encryptedPreMasterSecret,
	encryptedPreMasterSecretToByteString,
	rawEncryptedPreMasterSecret
) where

-- import Control.Applicative
-- import Numeric

-- import Data.Word
import qualified Data.ByteString as BS

import Tools

data EncryptedPreMasterSecret =
	EncryptedPreMasterSecret BS.ByteString
	deriving Show

encryptedPreMasterSecretToByteString :: EncryptedPreMasterSecret -> BS.ByteString
encryptedPreMasterSecretToByteString (EncryptedPreMasterSecret body) =
	bodyToBS 2 body

encryptedPreMasterSecret :: BS.ByteString ->
	Either String (EncryptedPreMasterSecret, BS.ByteString)
encryptedPreMasterSecret src = do
	(body, rest) <- getBody 2 src
	return (EncryptedPreMasterSecret body, rest)

rawEncryptedPreMasterSecret :: EncryptedPreMasterSecret -> BS.ByteString
rawEncryptedPreMasterSecret (EncryptedPreMasterSecret bs) = bs
