{-# LANGUAGE OverloadedStrings, TypeFamilies, ScopedTypeVariables,
	TupleSections #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module KeyExchange (
	verifyServerKeyExchange,
	integerToByteString,

	Base(..),
) where

import Control.Applicative
import Control.Monad

import ByteStringMonad
import Data.Bits
import qualified Data.ByteString as BS

import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA
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

verifyServerKeyExchange :: Base b =>
	RSA.PublicKey -> BS.ByteString -> BS.ByteString -> BS.ByteString ->
	Either String (b, Public b)
verifyServerKeyExchange pub cr sr ske = let
	Right (t, _) = ret
	ret = ( do
		(bd, sign) <- getBodySign t ske
		let	body = BS.concat [cr, sr, bd]
			cHash = SHA1.hash body
			unsign = BS.tail . BS.dropWhile (/= 0) . BS.drop 2 $ RSA.ep pub sign
		sHash <- fromASN =<< left show (decodeASN1' BER unsign)
		unless (cHash == sHash) $ Left $ "KeyExchange.verifyServerKeyExchange: " ++
			show cHash ++ " /= " ++ show sHash
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
