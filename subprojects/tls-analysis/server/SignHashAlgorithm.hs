{-# LANGUAGE OverloadedStrings, ScopedTypeVariables,
	FlexibleInstances, TypeFamilies, TupleSections #-}

module SignHashAlgorithm (
	SignatureAlgorithm(..), HashAlgorithm(..),
) where

import Data.Word
import qualified Data.ByteString as BS

import Prelude hiding (head, take)
import qualified Prelude

import qualified Codec.Bytable as B
import Codec.Bytable.BigEndian ()

data HashAlgorithm
	= HashAlgorithmSha1
	| HashAlgorithmSha224
	| HashAlgorithmSha256
	| HashAlgorithmSha384
	| HashAlgorithmSha512
	| HashAlgorithmRaw Word8
	deriving Show

instance B.Bytable HashAlgorithm where
	decode = byteStringToHashAlgorithm
	encode = hashAlgorithmToByteString

byteStringToHashAlgorithm :: BS.ByteString -> Either String HashAlgorithm
byteStringToHashAlgorithm bs = case BS.unpack bs of
	[ha] -> Right $ case ha of
		2 -> HashAlgorithmSha1
		3 -> HashAlgorithmSha224
		4 -> HashAlgorithmSha256
		5 -> HashAlgorithmSha384
		6 -> HashAlgorithmSha512
		_ -> HashAlgorithmRaw ha
	_ -> Left "Type.byteStringToHashAlgorithm"

hashAlgorithmToByteString :: HashAlgorithm -> BS.ByteString
hashAlgorithmToByteString HashAlgorithmSha1 = "\x02"
hashAlgorithmToByteString HashAlgorithmSha224 = "\x03"
hashAlgorithmToByteString HashAlgorithmSha256 = "\x04"
hashAlgorithmToByteString HashAlgorithmSha384 = "\x05"
hashAlgorithmToByteString HashAlgorithmSha512 = "\x06"
hashAlgorithmToByteString (HashAlgorithmRaw w) = BS.pack [w]

data SignatureAlgorithm
	= SignatureAlgorithmRsa
	| SignatureAlgorithmDsa
	| SignatureAlgorithmEcdsa
	| SignatureAlgorithmRaw Word8
	deriving Show

instance B.Bytable SignatureAlgorithm where
	decode = byteStringToSignatureAlgorithm
	encode = signatureAlgorithmToByteString

byteStringToSignatureAlgorithm :: BS.ByteString -> Either String SignatureAlgorithm
byteStringToSignatureAlgorithm bs = case BS.unpack bs of
	[sa] -> Right $ case sa of
		1 -> SignatureAlgorithmRsa
		2 -> SignatureAlgorithmDsa
		3 -> SignatureAlgorithmEcdsa
		_ -> SignatureAlgorithmRaw sa
	_ -> Left "Type.byteStringToSignatureAlgorithm"

signatureAlgorithmToByteString :: SignatureAlgorithm -> BS.ByteString
signatureAlgorithmToByteString SignatureAlgorithmRsa = "\x01"
signatureAlgorithmToByteString SignatureAlgorithmDsa = "\x02"
signatureAlgorithmToByteString SignatureAlgorithmEcdsa = "\x03"
signatureAlgorithmToByteString (SignatureAlgorithmRaw w) = BS.pack [w]
