{-# LANGUAGE OverloadedStrings, TypeFamilies, PackageImports #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module KeyExchange (
	ServerKeyExchange(..),
	verifyServerKeyExchange,
	integerToByteString,
	decodeServerKeyExchange,

	Base(..),
) where

import ByteStringMonad
import qualified Data.ByteString as BS

import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Crypto.Hash.SHA1 as SHA1

import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.Types
import Data.ASN1.Error

import qualified Crypto.Types.PubKey.DH as DH

import DiffieHellman

verifyServerKeyExchange :: RSA.PublicKey -> BS.ByteString -> BS.ByteString ->
	ServerKeyExchange -> (BS.ByteString, Either ASN1Error [ASN1])
verifyServerKeyExchange pub cr sr ske@(ServerKeyExchange _ps _ys _ha _sa s "") =
	let	body = BS.concat [cr, sr, getBody ske]
		hash = SHA1.hash body
		unSign = BS.tail . BS.dropWhile (/= 0) . BS.drop 2 $ RSA.ep pub s in
		(hash, decodeASN1' BER unSign)
verifyServerKeyExchange _ _ _ _ = error "verifyServerKeyExchange: bad"

getBody :: ServerKeyExchange -> BS.ByteString
getBody (ServerKeyExchange ps ys _ha _sa _ "") = encodeBasePublic ps ys
getBody _ = error "bad"

data ServerKeyExchange
	= ServerKeyExchange DH.Params DH.PublicNumber
		Word8 Word8 BS.ByteString
		BS.ByteString
	| ServerKeyExchangeRaw BS.ByteString
	deriving Show

decodeServerKeyExchange :: BS.ByteString -> Either String ServerKeyExchange
decodeServerKeyExchange = decodeKeyExchange

decodeKeyExchange :: BS.ByteString -> Either String ServerKeyExchange
decodeKeyExchange bs = do
	((b, p), bs') <- decodeBasePublic bs
	(hashA, sigA, sign) <- evalByteStringM parseSign bs'
	return $ ServerKeyExchange b p hashA sigA sign ""

parseSign :: ByteStringM (Word8, Word8, BS.ByteString)
parseSign = do
	hashA <- headBS
	sigA <- headBS
	sign <- takeLen 2
	"" <- whole
	return (hashA, sigA, sign)
