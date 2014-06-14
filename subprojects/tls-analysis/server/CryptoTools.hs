{-# LANGUAGE OverloadedStrings, PackageImports, TupleSections #-}

module CryptoTools (
	encryptMessage, decryptMessage, hashSha1, hashSha256,

	MS.MSVersion(..),
	MS.tupleToVersion,
	MS.ClientRandom(..), MS.ServerRandom(..),
	MS.generateMasterSecret, MS.generateKeyBlock, MS.generateFinished,

	ContentType(..),
	CipherSuite(..), KeyExchange(..), BulkEncryption(..),

	generateKeys_,
	finishedHash_,
	tlsEncryptMessage__,
	tlsDecryptMessage__,
) where

import Data.Word
import qualified Data.ByteString as BS
import "crypto-random" Crypto.Random
import qualified Crypto.Hash.SHA1 as SHA1
import qualified Crypto.Hash.SHA256 as SHA256
import Crypto.Cipher.AES
import CipherSuite

import qualified MasterSecret as MS

import qualified Codec.Bytable as B
import Codec.Bytable.BigEndian ()

import ContentType

type Hash = (BS.ByteString -> BS.ByteString, Int)

hashSha1, hashSha256 :: Hash
hashSha1 = (SHA1.hash, 20)
hashSha256 = (SHA256.hash, 32)

encryptMessage :: CPRG gen =>
	Hash -> gen -> BS.ByteString -> Word64 -> BS.ByteString ->
	ContentType -> (Word8, Word8) -> BS.ByteString -> (BS.ByteString, gen)
encryptMessage (hs, _) gen key sn mk ct (vmjr, vmnr) msg = 
	encrypt gen key . padd $ msg `BS.append` mac
	where
	mac = calcMac hs sn mk $ BS.concat [
		B.toByteString ct,
		B.toByteString vmjr,
		B.toByteString vmnr,
		B.addLength (undefined :: Word16) msg]

decryptMessage :: Hash ->
	BS.ByteString -> Word64 -> BS.ByteString ->
	ContentType -> (Word8, Word8) -> BS.ByteString -> Either String BS.ByteString
decryptMessage (hs, ml) key sn mk ct (vmjr, vmnr) enc = if mac == cmac then Right body else
	Left $ "CryptoTools.decryptMessage: bad MAC:\n\t" ++
		"Expected: " ++ show cmac ++ "\n\t" ++
		"Recieved: " ++ show mac ++ "\n\t" ++
		"ml: " ++ show ml ++ "\n"
	where
	bm = unpadd $ decrypt key enc
	(body, mac) = BS.splitAt (BS.length bm - ml) bm
	cmac = calcMac hs sn mk $ BS.concat [
		B.toByteString ct,
		B.toByteString vmjr,
		B.toByteString vmnr,
		B.addLength (undefined :: Word16) body]

calcMac :: (BS.ByteString -> BS.ByteString) ->
	Word64 -> BS.ByteString -> BS.ByteString -> BS.ByteString
calcMac hs sn mk inp =
	MS.hmac hs 64 mk $ B.toByteString sn `BS.append` inp

padd :: BS.ByteString -> BS.ByteString
padd bs = bs `BS.append` pd
	where
	plen = 16 - (BS.length bs + 1) `mod` 16
	pd = BS.replicate (plen + 1) $ fromIntegral plen

encrypt :: CPRG gen =>
	gen -> BS.ByteString -> BS.ByteString -> (BS.ByteString, gen)
encrypt gen key pln = let
	(iv, gen') = cprgGenerate 16 gen in
	(iv `BS.append` encryptCBC (initAES key) iv pln, gen')

unpadd :: BS.ByteString -> BS.ByteString
unpadd bs = BS.take (BS.length bs - plen) bs
	where
	plen = fromIntegral (myLast "unpadd" bs) + 1

myLast :: String -> BS.ByteString -> Word8
myLast msg "" = error msg
myLast _ bs = BS.last bs

decrypt :: BS.ByteString -> BS.ByteString -> BS.ByteString
decrypt key ivenc = let
	(iv, enc) = BS.splitAt 16 ivenc in
	decryptCBC (initAES key) iv enc

generateKeys_ :: BulkEncryption -> BS.ByteString -> BS.ByteString ->
	BS.ByteString -> Either String
	(BS.ByteString, BS.ByteString, BS.ByteString, BS.ByteString, BS.ByteString)
generateKeys_ be cr sr pms = do
	kl <- case be of
		AES_128_CBC_SHA -> Right 20
		AES_128_CBC_SHA256 -> Right 32
		_ -> Left "HandshakeMonad.generateKeys: not implemented"
	let	ms = MS.generateMasterSecret
			pms (MS.ClientRandom cr) (MS.ServerRandom sr)
		ems = MS.generateKeyBlock
			(MS.ClientRandom cr) (MS.ServerRandom sr) ms $ kl * 2 + 32
		[cwmk, swmk, cwk, swk] = divide [kl, kl, 16, 16] ems
	return (ms, cwmk, swmk, cwk, swk)
	where
	divide [] _ = []
	divide (n : ns) bs
		| bs == BS.empty = []
		| otherwise = let (x, xs) = BS.splitAt n bs in x : divide ns xs

finishedHash_ :: Bool -> BS.ByteString -> BS.ByteString -> BS.ByteString
finishedHash_ = MS.generateFinished MS.TLS12

tlsEncryptMessage_ :: CPRG gen => BulkEncryption -> ContentType ->
	BS.ByteString -> BS.ByteString -> Word64 -> BS.ByteString -> gen ->
	(BS.ByteString, gen)
tlsEncryptMessage_ be ct wk mk sn msg gen = let
	mhs = case be of
		AES_128_CBC_SHA -> Just hashSha1
		AES_128_CBC_SHA256 -> Just hashSha256
		BE_NULL -> Nothing
		_ -> error "not implemented" in
	case mhs of
		Just hs -> encryptMessage hs gen wk sn mk ct (3, 3) msg
		_ -> (msg, gen)

tlsEncryptMessage__ :: CPRG gen => BulkEncryption -> ContentType ->
	BS.ByteString -> BS.ByteString -> Word64 -> BS.ByteString ->
	Either String (gen -> (BS.ByteString, gen))
tlsEncryptMessage__ BE_NULL _ _ _ _ msg = Right (msg ,)
tlsEncryptMessage__ be ct wk mk sn msg = do
	return $ tlsEncryptMessage_ be ct wk mk sn msg

tlsDecryptMessage_ :: BulkEncryption -> ContentType ->
	BS.ByteString -> BS.ByteString -> Word64 -> BS.ByteString ->
	Either String BS.ByteString
tlsDecryptMessage_ be ct wk mk sn msg = do
	let mhs = case be of
		AES_128_CBC_SHA -> Just hashSha1
		AES_128_CBC_SHA256 -> Just hashSha256
		BE_NULL -> Nothing
		_ -> error "not implemented"
	case mhs of
		Just hs -> decryptMessage hs wk sn mk ct (3, 3) msg
		Nothing -> return msg

tlsDecryptMessage__ :: BulkEncryption -> ContentType ->
	BS.ByteString -> BS.ByteString -> Word64 -> BS.ByteString ->
	Either String BS.ByteString
tlsDecryptMessage__ BE_NULL _ _ _ _ msg = Right msg
tlsDecryptMessage__ be ct wk mk sn msg = do
	tlsDecryptMessage_ be ct wk mk sn msg
