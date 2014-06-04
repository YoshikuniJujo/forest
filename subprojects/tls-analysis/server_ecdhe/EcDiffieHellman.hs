{-# LANGUAGE OverloadedStrings, PackageImports, TypeFamilies #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module DiffieHellman (
	dhparams, dhprivate, sendServerKeyExchange,
	clientKeyExchange,
	DH.PrivateNumber,
	Base(..),
) where

import Control.Applicative
import qualified Data.ByteString as BS
import qualified Crypto.PubKey.DH as DH
import System.IO.Unsafe
import "crypto-random" Crypto.Random

import KeyExchange

import Base

dhparams :: DH.Params
dhparams = unsafePerformIO $ do
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	let	(ps, _g') = DH.generateParams g 512 2
	return ps

dhprivate :: Base b => b -> IO (Secret b)
dhprivate b = do
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	let	(pr, _g') = generateSecret g b
	return pr
	
decodeParams :: BS.ByteString -> Either String DH.Params
decodeParams = evalByteStringM $ do
	dhP <- byteStringToInteger <$> takeLen 2
	dhG <- byteStringToInteger <$> takeLen 2
	return (DH.Params dhP dhG)

decodePublicNumber :: BS.ByteString -> Either String DH.PublicNumber
decodePublicNumber = Right . fromInteger . byteStringToInteger

encodeParams :: DH.Params -> BS.ByteString
encodeParams (DH.Params dhP dhG) = BS.concat [
	lenBodyToByteString 2 $ integerToByteString dhP,
	lenBodyToByteString 2 $ integerToByteString dhG
 ]

encodePublicNumber :: DH.PublicNumber -> BS.ByteString
encodePublicNumber = lenBodyToByteString 2 . integerToByteString . fromIntegral

instance Base DH.Params where
	type Param DH.Params = (Int, Integer)
	type Secret DH.Params = DH.PrivateNumber
	type Public DH.Params = DH.PublicNumber
	generateBase rng (bits, gen) = DH.generateParams rng bits gen
	generateSecret rng ps = DH.generatePrivate rng ps
	calculatePublic ps sn = DH.calculatePublic ps sn
	calculateCommon ps sn pn = integerToByteString . fromIntegral $ DH.getShared ps sn pn
	encodeBase = encodeParams
	decodeBase bs = let Right ps = decodeParams bs in ps
	encodePublic _ = encodePublicNumber
	decodePublic _ bs = let Right pn = decodePublicNumber bs in pn
