{-# LANGUAGE OverloadedStrings, PackageImports, TypeFamilies #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module DiffieHellman (
	dhparams, dhprivate,
	DH.PrivateNumber,
	Base(..),
--	SecretKey(..),

--	byteStringToInteger,

--	ServerKeyExchange(..),
--	addSign,
--	serverKeyExchangeToByteString,
) where

import Control.Applicative
import qualified Data.ByteString as BS
import qualified Crypto.PubKey.DH as DH
import qualified Crypto.Types.PubKey.DH as DH
import System.IO.Unsafe
import "crypto-random" Crypto.Random

import KeyExchange
import qualified Codec.Bytable as B

import Data.Word

-- import ByteStringMonad

dhparams :: DH.Params
dhparams = unsafePerformIO $ -- do
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
decodeParams = B.evalBytableM $ DH.Params <$> B.take 2 <*> B.take 2

decodePublicNumber :: BS.ByteString -> Either String DH.PublicNumber
decodePublicNumber =
	Right . fromInteger . either error id . B.fromByteString . BS.drop 2

encodeParams :: DH.Params -> BS.ByteString
encodeParams (DH.Params dhP dhG) = BS.concat [
	B.addLength (undefined :: Word16) $ B.toByteString dhP,
	B.addLength (undefined :: Word16) $ B.toByteString dhG
 ]

encodePublicNumber :: DH.PublicNumber -> BS.ByteString
encodePublicNumber =
	B.addLength (undefined :: Word16) . B.toByteString . \(DH.PublicNumber pn) -> pn

instance Base DH.Params where
	type Param DH.Params = (Int, Integer)
	type Secret DH.Params = DH.PrivateNumber
	type Public DH.Params = DH.PublicNumber
	generateBase rng (bits, gen) = DH.generateParams rng bits gen
	generateSecret = DH.generatePrivate
	calculatePublic = DH.calculatePublic
	calculateCommon ps sn pn = B.toByteString .
		(\(DH.SharedKey i) -> i) $ DH.getShared ps sn pn

instance B.Bytable DH.Params where
	fromByteString = decodeParams
	toByteString = encodeParams

instance B.Bytable DH.PublicNumber where
	fromByteString = decodePublicNumber
	toByteString = encodePublicNumber
