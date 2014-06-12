{-# LANGUAGE OverloadedStrings, PackageImports, ScopedTypeVariables,
	FlexibleInstances, TypeFamilies, TupleSections #-}

module Types (
	Version(..),
	Random(..),
	NamedCurve(..),
	SignatureAlgorithm(..), HashAlgorithm(..),
	takeLen,
) where

import Data.Word
import qualified Data.ByteString as BS

import Prelude hiding (head, take)
import qualified Prelude

import Data.Bits
import Data.ByteString (ByteString)
import "monads-tf" Control.Monad.State

import Numeric

import qualified Codec.Bytable as B
import Codec.Bytable.BigEndian ()

data Version
	= Version Word8 Word8
	deriving (Show, Eq, Ord)

data Random = Random BS.ByteString

data NamedCurve
	= Secp256r1
	| Secp384r1
	| Secp521r1
	| NamedCurveRaw Word16
	deriving Show

data SignatureAlgorithm
	= SignatureAlgorithmRsa
	| SignatureAlgorithmDsa
	| SignatureAlgorithmEcdsa
	| SignatureAlgorithmRaw Word8
	deriving Show

data HashAlgorithm
	= HashAlgorithmSha1
	| HashAlgorithmSha224
	| HashAlgorithmSha256
	| HashAlgorithmSha384
	| HashAlgorithmSha512
	| HashAlgorithmRaw Word8
	deriving Show

instance B.Bytable HashAlgorithm where
	fromByteString = byteStringToHashAlgorithm
	toByteString = hashAlgorithmToByteString

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

hashAlgorithmToByteString :: HashAlgorithm -> ByteString
hashAlgorithmToByteString HashAlgorithmSha1 = "\x02"
hashAlgorithmToByteString HashAlgorithmSha224 = "\x03"
hashAlgorithmToByteString HashAlgorithmSha256 = "\x04"
hashAlgorithmToByteString HashAlgorithmSha384 = "\x05"
hashAlgorithmToByteString HashAlgorithmSha512 = "\x06"
hashAlgorithmToByteString (HashAlgorithmRaw w) = BS.pack [w]

instance B.Bytable SignatureAlgorithm where
	fromByteString = byteStringToSignatureAlgorithm
	toByteString = signatureAlgorithmToByteString

byteStringToSignatureAlgorithm :: BS.ByteString -> Either String SignatureAlgorithm
byteStringToSignatureAlgorithm bs = case BS.unpack bs of
	[sa] -> Right $ case sa of
		1 -> SignatureAlgorithmRsa
		2 -> SignatureAlgorithmDsa
		3 -> SignatureAlgorithmEcdsa
		_ -> SignatureAlgorithmRaw sa
	_ -> Left "Type.byteStringToSignatureAlgorithm"

signatureAlgorithmToByteString :: SignatureAlgorithm -> ByteString
signatureAlgorithmToByteString SignatureAlgorithmRsa = "\x01"
signatureAlgorithmToByteString SignatureAlgorithmDsa = "\x02"
signatureAlgorithmToByteString SignatureAlgorithmEcdsa = "\x03"
signatureAlgorithmToByteString (SignatureAlgorithmRaw w) = BS.pack [w]

instance B.Bytable NamedCurve where
	fromByteString = byteStringToNamedCurve
	toByteString = namedCurveToByteString

byteStringToNamedCurve :: ByteString -> Either String NamedCurve
byteStringToNamedCurve bs = case BS.unpack bs of
	[w1, w2] -> Right $ case fromIntegral w1 `shiftL` 8 .|. fromIntegral w2 of
		23 -> Secp256r1
		24 -> Secp384r1
		25 -> Secp521r1
		nc -> NamedCurveRaw nc
	_ -> Left "Types.byteStringToNamedCurve"

namedCurveToByteString :: NamedCurve -> ByteString
namedCurveToByteString (Secp256r1) = word16ToByteString 23
namedCurveToByteString (Secp384r1) = word16ToByteString 24
namedCurveToByteString (Secp521r1) = word16ToByteString 25
namedCurveToByteString (NamedCurveRaw nc) = word16ToByteString nc

takeInt :: Monad m => (Int -> m BS.ByteString) -> Int -> m Int
takeInt rd = (byteStringToInt `liftM`) . rd

takeLen :: Monad m => (Int -> m BS.ByteString) -> Int -> m ByteString
takeLen rd n = do
	l <- takeInt rd n
	rd l

word16ToByteString :: Word16 -> ByteString
word16ToByteString w = BS.pack [fromIntegral (w `shiftR` 8), fromIntegral w]

byteStringToInt :: ByteString -> Int
byteStringToInt bs = wordsToInt (BS.length bs - 1) $ BS.unpack bs

wordsToInt :: Int -> [Word8] -> Int
wordsToInt n _ | n < 0 = 0
wordsToInt _ [] = 0
wordsToInt n (x : xs) = fromIntegral x `shift` (n * 8) .|. wordsToInt (n - 1) xs

instance B.Bytable Version where
	fromByteString bs = case BS.unpack bs of
		[vmjr, vmnr] -> Right $ Version vmjr vmnr
		_ -> Left "Types.hs: B.Bytable Version"
	toByteString (Version vmjr vmnr) = BS.pack [vmjr, vmnr]

instance Show Random where
	show (Random r) =
		"(Random " ++ concatMap (`showHex` "") (BS.unpack r) ++ ")"

instance B.Bytable Random where
	fromByteString = Right . Random
	toByteString (Random bs) = bs
