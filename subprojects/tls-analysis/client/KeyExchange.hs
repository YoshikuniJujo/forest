{-# LANGUAGE OverloadedStrings, TypeFamilies, ScopedTypeVariables,
	TupleSections #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module KeyExchange (
	verifyServerKeyExchange,
	integerToByteString,

	Base(..), PublicKey(..),
) where

import Control.Applicative
import Control.Monad

import ByteStringMonad
import Data.Maybe
import Data.Bits
import qualified Data.ByteString as BS

import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.Hash.SHA1 as SHA1

import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.Types

-- import DiffieHellman
import Base

import Control.Arrow

fromASN :: [ASN1] -> Either String BS.ByteString
fromASN a = case a of
	[Start Sequence, Start Sequence, OID [1, 3, 14, 3, 2, 26],
		Null, End Sequence, OctetString o, End Sequence] -> Right o
	_ -> Left "KeyExchange.fromASN"

class PublicKey pk where
	verify :: pk -> BS.ByteString -> BS.ByteString -> Bool

instance PublicKey RSA.PublicKey where
	verify = verifyRsa

instance PublicKey ECDSA.PublicKey where
	verify = verifyEcdsa

verifyEcdsa :: ECDSA.PublicKey -> BS.ByteString -> BS.ByteString -> Bool
verifyEcdsa pk bd sn = let
	s = decodeSignature sn in
	ECDSA.verify SHA1.hash pk s bd

decodeSignature :: BS.ByteString -> ECDSA.Signature
decodeSignature bs = let EcdsaSign _ (_, r) (_, s) = decodeEcdsaSign bs in
	ECDSA.Signature r s

decodeEcdsaSign :: BS.ByteString -> EcdsaSign
decodeEcdsaSign bs = fromJust $ do
	(rt, rest) <- BS.uncons rs
	(rl, rest') <- BS.uncons rest
	let (rb, rest'') = BS.splitAt (fromIntegral rl) rest'
	(st, rest''') <- BS.uncons rest''
	(sl, rest'''') <- BS.uncons rest'''
	let (sb, "") = BS.splitAt (fromIntegral sl) rest''''
	return $ EcdsaSign t
		(rt, byteStringToInteger rb)
		(st, byteStringToInteger sb)
	where
	(h, rs) = BS.splitAt 2 bs
	[t, _l] = BS.unpack h

data EcdsaSign
	= EcdsaSign Word8 (Word8, Integer) (Word8, Integer)
	deriving Show

verifyRsa :: RSA.PublicKey -> BS.ByteString -> BS.ByteString -> Bool
verifyRsa pk bd sn = const False ||| id $ do
	let	cHash = SHA1.hash bd
		unsign = BS.tail . BS.dropWhile (/= 0) . BS.drop 2 $ RSA.ep pk sn
	sHash <- fromASN =<< left show (decodeASN1' BER unsign)
	return $ cHash == sHash

verifyServerKeyExchange :: (Base b, PublicKey pk) => pk ->
	BS.ByteString -> BS.ByteString -> BS.ByteString ->
		Either String (b, Public b)
verifyServerKeyExchange pub cr sr ske = let
	Right (t, _) = ret
	ret = ( do
		(bd, sn) <- getBodySign t ske
		let	body = BS.concat [cr, sr, bd]
		{-
			cHash = SHA1.hash body
			unsign = BS.tail . BS.dropWhile (/= 0) . BS.drop 2 $ RSA.ep pub sn
		sHash <- fromASN =<< left show (decodeASN1' BER unsign)
		-}
--		unless (cHash == sHash) . Left $ "KeyExchange.verifyServerKeyExchange: " ++
		unless (verify pub body sn) . Left $
			"KeyExchange.verifyServerKeyExchange: " -- ++
--			show cHash ++ " /= " ++ show sHash
		getBasePublic ske) in ret

getBasePublic :: Base b => BS.ByteString -> Either String (b, Public b)
getBasePublic bs = fst <$> decodeBasePublic bs

getBodySign :: Base b => b ->
	BS.ByteString -> Either String (BS.ByteString, BS.ByteString)
getBodySign t bs = do
	((b, p), bs') <- decodeBasePublic bs
	(_, _, sign) <- decodeSign bs'
	return (encodeBasePublic (b `asTypeOf` t) p, sign)

decodeSign :: BS.ByteString -> Either String (Word8, Word8, BS.ByteString)
decodeSign = evalByteStringM parseSign

parseSign :: ByteStringM (Word8, Word8, BS.ByteString)
parseSign = do
	hashA <- headBS
	sigA <- headBS
	sign <- takeLen 2
	"" <- whole
	return (hashA, sigA, sign)

integerToByteString :: Integer -> BS.ByteString
integerToByteString = BS.pack . toWords

toWords :: Integer -> [Word8]
toWords = reverse . integerToWords

integerToWords :: Integer -> [Word8]
integerToWords 0 = []
integerToWords i = fromIntegral i : integerToWords (i `shiftR` 8)

byteStringToInteger :: BS.ByteString -> Integer
byteStringToInteger = toI . BS.unpack

toI :: [Word8] -> Integer
toI = wordsToInteger . reverse

wordsToInteger :: [Word8] -> Integer
wordsToInteger [] = 0
wordsToInteger (w : ws) = fromIntegral w .|. (wordsToInteger ws `shiftL` 8)
