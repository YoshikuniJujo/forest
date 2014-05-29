{-# LANGUAGE OverloadedStrings #-}

module Basic (
	Fragment(..),
	Version(..), byteStringToVersion, versionToByteString,
	ContentType(..), byteStringToContentType, contentTypeToByteString,
	Random(..), CipherSuite(..),
	showKey, showKeySingle, word64ToByteString,
	byteStringToInt, intToByteString,
	lenBodyToByteString, fromInt, fst3,
) where

import Data.Bits
import Data.Word
import Data.ByteString (ByteString, pack, unpack)
import qualified Data.ByteString as BS
import Numeric

data Fragment
	= Fragment ContentType Version ByteString
	deriving Show

data Version
	= Version Word8 Word8
	deriving Show

byteStringToVersion :: ByteString -> Version
byteStringToVersion v = let [vmjr, vmnr] = unpack v in Version vmjr vmnr

versionToByteString :: Version -> ByteString
versionToByteString (Version vmjr vmnr) = pack [vmjr, vmnr]

data ContentType
	= ContentTypeChangeCipherSpec
	| ContentTypeAlert
	| ContentTypeHandshake
	| ContentTypeApplicationData
	| ContentTypeRaw Word8
	deriving Show

byteStringToContentType :: ByteString -> ContentType
byteStringToContentType "\20" = ContentTypeChangeCipherSpec
byteStringToContentType "\21" = ContentTypeAlert
byteStringToContentType "\22" = ContentTypeHandshake
byteStringToContentType "\23" = ContentTypeApplicationData
byteStringToContentType bs = let [ct] = unpack bs in ContentTypeRaw ct

contentTypeToByteString :: ContentType -> ByteString
contentTypeToByteString ContentTypeChangeCipherSpec = pack [20]
contentTypeToByteString ContentTypeAlert = pack [21]
contentTypeToByteString ContentTypeHandshake = pack [22]
contentTypeToByteString ContentTypeApplicationData = pack [23]
contentTypeToByteString (ContentTypeRaw ct) = pack [ct]

data Random = Random ByteString

data CipherSuite
	= TLS_NULL_WITH_NULL_NULL
	| TLS_RSA_WITH_AES_128_CBC_SHA
	| TLS_DHE_RSA_WITH_AES_128_CBC_SHA
	| TLS_ECDHE_PSK_WITH_NULL_SHA
	| TLS_RSA_WITH_AES_128_CBC_SHA256
	| TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
	| TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
	| CipherSuiteRaw Word8 Word8
	deriving (Show, Eq)

showKeySingle :: ByteString -> String
showKeySingle = unwords . map showH . BS.unpack

showKey :: ByteString -> String
showKey = init . unlines . map unwords . separateN 16 . map showH . BS.unpack
	where
	separateN _ [] = []
	separateN n xs = Prelude.take n xs : separateN n (drop n xs)

showH :: Word8 -> String
showH w = let s = showHex w "" in replicate (2 - length s) '0' ++ s

word64ToByteString :: Word64 -> ByteString
word64ToByteString w64 = BS.replicate (8 - BS.length bs) 0 `BS.append` bs
	where
	bs = BS.reverse $ wtb w64
	wtb 0 = ""
	wtb w = fromIntegral (w .&. 0xff) `BS.cons` wtb (w `shiftR` 8)

byteStringToInt :: ByteString -> Int
byteStringToInt bs = wordsToInt (BS.length bs - 1) $ BS.unpack bs

wordsToInt :: Int -> [Word8] -> Int
wordsToInt n _ | n < 0 = 0
wordsToInt _ [] = 0
wordsToInt n (x : xs) = fromIntegral x `shift` (n * 8) .|. wordsToInt (n - 1) xs

intToByteString :: Int -> Int -> ByteString
intToByteString n = BS.pack . reverse . intToWords n

intToWords :: Int -> Int -> [Word8]
intToWords 0 _ = []
intToWords n i = fromIntegral i : intToWords (n - 1) (i `shiftR` 8)

lenBodyToByteString :: Int -> ByteString -> ByteString
lenBodyToByteString n bs = intToByteString n (BS.length bs) `BS.append` bs

fromInt :: Integral i => Int -> i
fromInt = fromIntegral

fst3 :: (a, b, c) -> a
fst3 (x, _, _) = x
