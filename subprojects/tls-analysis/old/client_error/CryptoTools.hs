{-# LANGUAGE PackageImports #-}

module CryptoTools (
	encryptMessage, decryptMessage, hashSha1, hashSha256,

	MS.MSVersion(..), MS.versionToVersion,
	MS.ClientRandom(..), MS.ServerRandom(..),
	MS.generateMasterSecret, MS.generateKeyBlock, MS.generateFinished,
) where

import Data.Word
import qualified Data.ByteString as BS
import "crypto-random" Crypto.Random
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA256 as SHA256
import Crypto.Cipher.AES

import qualified MasterSecret as MS
import Basic

type Hash = (BS.ByteString -> BS.ByteString, Int)

hashSha1, hashSha256 :: Hash
hashSha1 = (SHA1.hash, 20)
hashSha256 = (SHA256.hash, 32)

encryptMessage :: Hash -> SystemRNG -> BS.ByteString -> Word64 -> BS.ByteString ->
	ContentType -> Version -> BS.ByteString -> (BS.ByteString, SystemRNG)
encryptMessage (hs, ml) gen key sn mk ct v msg = 
	encrypt gen key . padd $ msg `BS.append` mac
	where
	mac = calcMac hs sn mk $ BS.concat [
		contentTypeToByteString ct,
		versionToByteString v,
		lenBodyToByteString 2 msg]

decryptMessage :: Hash -> BS.ByteString -> Word64 -> BS.ByteString ->
	ContentType -> Version -> BS.ByteString -> Either String BS.ByteString
decryptMessage (hs, ml) key sn mk ct v enc = if mac == cmac then Right body else
	Left $ "decryptMessage: bad MAC: \n\t" ++
		"expected: " ++ show cmac ++ "\n\t" ++
		"recieved: " ++ show mac ++ "\n"
	where
	bm = unpadd $ decrypt key enc
	(body, mac) = BS.splitAt (BS.length bm - ml) bm
	cmac = calcMac hs sn mk $ BS.concat [
		contentTypeToByteString ct,
		versionToByteString v,
		lenBodyToByteString 2 body]

calcMac :: (BS.ByteString -> BS.ByteString) -> Word64 -> BS.ByteString -> BS.ByteString -> BS.ByteString
calcMac hs sn mk inp =
	MS.hmac hs 64 mk $ word64ToByteString sn `BS.append` inp

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
