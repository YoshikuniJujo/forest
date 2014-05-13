{-# LANGUAGE TupleSections, OverloadedStrings #-}

module Parts (
	list, listToByteString,
	ContentType(..), contentType, contentTypeToByteString,
	Version, version, versionGen, versionToByteString,
	Random(..), random, randomToByteString,
	SessionId, sessionId, sessionIdToByteString,
	CipherSuite, cipherSuite, cipherSuiteToByteString,
	CompressionMethod, compressionMethod, compressionMethodToByteString,
) where

import Control.Applicative
import Numeric

import Data.Word
import qualified Data.ByteString as BS

import Tools

data ContentType
	= ContentTypeHandshake
	| ContentTypeOthers Word8
	deriving Show

contentType :: Word8 -> ContentType
contentType 22 = ContentTypeHandshake
contentType w = ContentTypeOthers w

contentTypeToByteString :: ContentType -> BS.ByteString
contentTypeToByteString ContentTypeHandshake = BS.pack [22]
contentTypeToByteString (ContentTypeOthers w) = BS.pack [w]

data Version
	= Version Word8 Word8
	deriving Show

versionToByteString :: Version -> BS.ByteString
versionToByteString (Version w1 w2) = BS.pack [w1, w2]

versionGen :: Word8 -> Word8 -> Version
versionGen = Version

version :: BS.ByteString -> Either String (Version, BS.ByteString)
version src = do
	(v, rest) <- eitherSplitAt "version" 2 src
	let [vmjr, vmnr] = BS.unpack v
	return (Version vmjr vmnr, rest)

data Random
	= Random BS.ByteString

instance Show Random where
	show (Random bs) =
		"(Random " ++ concatMap (`showHex` "") (BS.unpack bs) ++ ")"

randomToByteString :: Random -> BS.ByteString
randomToByteString (Random bs) = bs

random :: BS.ByteString -> Either String (Random, BS.ByteString)
random src = do
	(r, rest) <- eitherSplitAt "random" 32 src
	return (Random r, rest)

data SessionId
	= SessionId BS.ByteString

instance Show SessionId where
	show (SessionId bs) =
		"(SessionId " ++ concatMap (`showHex` "") (BS.unpack bs) ++ ")"

sessionIdToByteString :: SessionId -> BS.ByteString
sessionIdToByteString (SessionId sid) = lenToBS 1 sid `BS.append` sid

sessionId :: BS.ByteString -> Either String (SessionId, BS.ByteString)
sessionId src = do
	(len, r1) <- bsToLen 1 src
	(sid, r2) <- eitherSplitAt "sessionId" len r1
	return (SessionId sid, r2)

data CipherSuite
	= TLS_RSA_WITH_AES_128_CBC_SHA
	| CipherSuite Word8 Word8
	deriving Show

cipherSuiteToByteString :: CipherSuite -> BS.ByteString
cipherSuiteToByteString TLS_RSA_WITH_AES_128_CBC_SHA = "\x00\x2f"
cipherSuiteToByteString (CipherSuite w1 w2) = BS.pack [w1, w2]

cipherSuite :: BS.ByteString -> Either String (CipherSuite, BS.ByteString)
cipherSuite src = do
	(cs, rest) <- eitherSplitAt "cipherSuite" 2 src
	let [w1, w2] = BS.unpack cs
	return (cipherSuiteSelect w1 w2, rest)

cipherSuiteSelect :: Word8 -> Word8 -> CipherSuite
cipherSuiteSelect 0x00 0x2f = TLS_RSA_WITH_AES_128_CBC_SHA
cipherSuiteSelect w1 w2 = CipherSuite w1 w2

listToByteString :: Int -> (a -> BS.ByteString) -> [a] -> BS.ByteString
listToByteString n toBS xs = lenToBS n body `BS.append` body
	where
	body = BS.concat $ map toBS xs

list :: Int -> (BS.ByteString -> Either String (a, BS.ByteString)) ->
	BS.ByteString -> Either String ([a], BS.ByteString)
list n prs src = do
	(len, r1) <- bsToLen n src
	(body, r2) <- eitherSplitAt "list" len r1
	(, r2) <$> takeWhole prs body

takeWhole :: (BS.ByteString -> Either String (a, BS.ByteString)) -> 
	BS.ByteString -> Either String [a]
takeWhole prs src
	| src == BS.empty = return []
	| otherwise = do
		(ret, rest) <- prs src
		(ret :) <$> takeWhole prs rest

data CompressionMethod
	= CompressionMethodNull
	| CompressionMethod Word8
	deriving Show

compressionMethodToByteString :: CompressionMethod -> BS.ByteString
compressionMethodToByteString CompressionMethodNull = "\x00"
compressionMethodToByteString (CompressionMethod w) = BS.pack [w]

compressionMethod :: BS.ByteString -> Either String (CompressionMethod, BS.ByteString)
compressionMethod src = do
	(w, rest) <- eitherUncons src
	return (compressionMethodSelect w, rest)

compressionMethodSelect :: Word8 -> CompressionMethod
compressionMethodSelect 0 = CompressionMethodNull
compressionMethodSelect w = CompressionMethod w
