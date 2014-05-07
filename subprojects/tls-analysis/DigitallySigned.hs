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
import Parts

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
