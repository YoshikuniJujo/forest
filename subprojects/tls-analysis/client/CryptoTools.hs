{-# LANGUAGE PackageImports #-}

module CryptoTools (
	encryptMessage,
	encrypt, decrypt, calcMac, padd, unpadd,

	MS.MSVersion(..), MS.versionToVersion,
	MS.ClientRandom(..), MS.ServerRandom(..),
	MS.generateMasterSecret, MS.generateKeyBlock, MS.generateFinished,
) where

import Data.Word
import qualified Data.ByteString as BS
import "crypto-random" Crypto.Random
import qualified Crypto.Hash.SHA1 as SHA1
import Crypto.Cipher.AES

import qualified MasterSecret as MS
import Basic

encryptMessage :: SystemRNG -> BS.ByteString -> Word64 -> BS.ByteString ->
	ContentType -> Version -> BS.ByteString -> (BS.ByteString, SystemRNG)
encryptMessage gen key sn mk ct v msg = 
	encrypt gen key . padd $ msg `BS.append` mac
	where
	mac = calcMac sn mk $ BS.concat [
		contentTypeToByteString ct,
		versionToByteString v,
		lenBodyToByteString 2 msg]

calcMac :: Word64 -> BS.ByteString -> BS.ByteString -> BS.ByteString
calcMac sn mk inp =
	MS.hmac SHA1.hash 64 mk $ word64ToByteString sn `BS.append` inp

padd :: BS.ByteString -> BS.ByteString
padd bs = bs `BS.append` pd
	where
	plen = 16 - (BS.length bs + 1) `mod` 16
	pd = BS.replicate (plen + 1) $ fromIntegral plen

encrypt :: SystemRNG ->
	BS.ByteString -> BS.ByteString -> (BS.ByteString, SystemRNG)
encrypt gen key pln = let
	(iv, gen') = cprgGenerate 16 gen in
	(iv `BS.append` encryptCBC (initAES key) iv pln, gen')

unpadd :: BS.ByteString -> BS.ByteString
unpadd bs = BS.take (BS.length bs - plen) bs
	where
	plen = fromIntegral (BS.last bs) + 1

decrypt :: BS.ByteString -> BS.ByteString -> BS.ByteString
decrypt key ivenc = let
	(iv, enc) = BS.splitAt 16 ivenc in
	decryptCBC (initAES key) iv enc
