{-# LANGUAGE OverloadedStrings #-}

module DigitallySigned (
	DigitallySigned, parseDigitallySigned, digitallySignedToByteString,
	digitallySignedSign
) where

import Prelude hiding (head)

import Control.Applicative
import qualified Data.ByteString as BS
import ByteStringMonad
import ToByteString

data DigitallySigned
	= DigitallySigned (HashAlgorithm, SignatureAlgorithm) ByteString
	| DigitallySignedRaw ByteString
	deriving Show

digitallySignedSign :: DigitallySigned -> Maybe ByteString
digitallySignedSign (DigitallySigned _ s) = Just s
digitallySignedSign _ = Nothing

parseDigitallySigned :: ByteStringM DigitallySigned
parseDigitallySigned = DigitallySigned
	<$> ((,) <$> parseHashAlgorithm <*> parseSignatureAlgorithm)
	<*> takeLen 2

digitallySignedToByteString :: DigitallySigned -> ByteString
digitallySignedToByteString (DigitallySigned (ha, sa) bs) = BS.concat [
	hashAlgorithmToByteString ha,
	signatureAlgorithmToByteString sa,
	lenBodyToByteString 2 bs ]
digitallySignedToByteString (DigitallySignedRaw bs) = bs

data HashAlgorithm
	= HashAlgorithmSha256
	| HashAlgorithmRaw Word8
	deriving Show

parseHashAlgorithm :: ByteStringM HashAlgorithm
parseHashAlgorithm = do
	ha <- head
	return $ case ha of
		4 -> HashAlgorithmSha256
		_ -> HashAlgorithmRaw ha

hashAlgorithmToByteString :: HashAlgorithm -> ByteString
hashAlgorithmToByteString HashAlgorithmSha256 = "\x04"
hashAlgorithmToByteString (HashAlgorithmRaw w) = pack [w]

data SignatureAlgorithm
	= SignatureAlgorithmRsa
	| SignatureAlgorithmRaw Word8
	deriving Show

parseSignatureAlgorithm :: ByteStringM SignatureAlgorithm
parseSignatureAlgorithm = do
	sa <- head
	return $ case sa of
		1 -> SignatureAlgorithmRsa
		_ -> SignatureAlgorithmRaw sa

signatureAlgorithmToByteString :: SignatureAlgorithm -> ByteString
signatureAlgorithmToByteString SignatureAlgorithmRsa = "\x01"
signatureAlgorithmToByteString (SignatureAlgorithmRaw w) = pack [w]
