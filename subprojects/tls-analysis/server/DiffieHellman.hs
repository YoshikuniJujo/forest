{-# LANGUAGE OverloadedStrings, PackageImports, TypeFamilies #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module DiffieHellman (
	dhparams, dhprivate,
	sndServerKeyExchange,
	rcvClientKeyExchange,
	DH.PrivateNumber,
	Base(..),
	SecretKey,

	byteStringToInteger,
) where

import Control.Applicative
import qualified Data.ByteString as BS
import qualified Crypto.PubKey.DH as DH
import qualified Crypto.Types.PubKey.DH as DH
import System.IO.Unsafe
import "crypto-random" Crypto.Random

import KeyExchange

import ByteStringMonad

dhparams :: DH.Params
dhparams = unsafePerformIO $ do
	readIO =<< readFile "dh-params.txt"
{-
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	let	(ps, _g') = DH.generateParams g 512 2
	return ps
	-}

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
decodePublicNumber = Right . fromInteger . byteStringToInteger . BS.drop 2

encodeParams :: DH.Params -> BS.ByteString
encodeParams (DH.Params dhP dhG) = BS.concat [
	lenBodyToByteString 2 $ integerToByteString dhP,
	lenBodyToByteString 2 $ integerToByteString dhG
 ]

encodePublicNumber :: DH.PublicNumber -> BS.ByteString
encodePublicNumber =
	lenBodyToByteString 2 . integerToByteString . \(DH.PublicNumber pn) -> pn

instance Base DH.Params where
	type Param DH.Params = (Int, Integer)
	type Secret DH.Params = DH.PrivateNumber
	type Public DH.Params = DH.PublicNumber
	generateBase rng (bits, gen) = DH.generateParams rng bits gen
	generateSecret = DH.generatePrivate
	calculatePublic = DH.calculatePublic
	calculateCommon ps sn pn = integerToByteString .
		(\(DH.SharedKey i) -> i) $ DH.getShared ps sn pn
	encodeBase = encodeParams
	decodeBase bs = let Right ps = decodeParams bs in ps
	encodePublic _ = encodePublicNumber
	decodePublic _ bs = let Right pn = decodePublicNumber bs in pn
