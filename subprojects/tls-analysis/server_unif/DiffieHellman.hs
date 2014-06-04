{-# LANGUAGE OverloadedStrings, PackageImports, TypeFamilies #-}

module DiffieHellman (
	dhparams, dhprivate, sendServerKeyExchange,
	clientKeyExchange,
	DH.PrivateNumber,
	Base(..),
) where

import Control.Applicative
import Data.Maybe
import qualified Data.ByteString as BS
import qualified Crypto.PubKey.DH as DH
import System.IO.Unsafe
import "crypto-random" Crypto.Random
import qualified Crypto.PubKey.RSA as RSA

import Fragment
import Types
import KeyExchange
import Content

version :: Version
version = Version 3 3

dhparams :: DH.Params
dhparams = unsafePerformIO $ do
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	let	(ps, _g') = DH.generateParams g 512 2
	return ps

dhprivate :: Base b => b -> IO (Secret b)
dhprivate b = do
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	let	(pr, _g') = generateSecret g b -- DH.generatePrivate g dhparams
	return pr
	
sendServerKeyExchange ::
	Base b => b -> Secret b -> RSA.PrivateKey -> BS.ByteString -> TlsIo ()
sendServerKeyExchange ps dhsk pk sr = do
	Just cr <- getClientRandom
	let	ske = HandshakeServerKeyExchange . addSign pk cr sr $
			ServerKeyExchange'
				(encodeBase ps)
				(encodePublic ps $ calculatePublic ps dhsk)
				2 1 "hogeru"
	{-
			ServerKeyExchange
				dhparams (DH.calculatePublic dhparams $
					dhprivate {- dhparams -})
				2 1 "hogeru" ""
				-}
	((>>) <$> writeFragment <*> fragmentUpdateHash) . contentListToFragment .
		map (ContentHandshake version) $ catMaybes [
		Just ske
	 ]

-- clientKeyExchange :: RSA.PrivateKey -> DH.PrivateNumber -> Version -> TlsIo ()
clientKeyExchange :: Base b => b -> Secret b -> Version -> TlsIo ()
clientKeyExchange dhps dhpn (Version _cvmjr _cvmnr) = do
	hs <- readHandshake (== version)
	case hs of
		HandshakeClientKeyExchange (EncryptedPreMasterSecret epms) -> do
			liftIO . putStrLn $ "CLIENT KEY: " ++ show epms
--			let pms = DH.getShared dhps dhpn $
--				byteStringToPublicNumber epms
			let pms = calculateCommon dhps dhpn $ decodePublic dhps epms
			generateKeys pms
--			generateKeys . integerToByteString $ fromIntegral pms
		_ -> throwError $ Alert AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"TlsServer.clientKeyExchange: not client key exchange"

readHandshake :: (Version -> Bool) -> TlsIo Handshake
readHandshake ck = do
	cnt <- readContent ck
	case cnt of
		ContentHandshake v hs
			| ck v -> return hs
			| otherwise -> throwError $ Alert
				AlertLevelFatal
				AlertDescriptionProtocolVersion
				"Not supported layer version"
		_ -> throwError . Alert
			AlertLevelFatal
			AlertDescriptionUnexpectedMessage $
			"Not Handshake: " ++ show cnt

readContent :: (Version -> Bool) -> TlsIo Content
readContent vc = do
	c <- getContent (readBufferContentType vc) (readByteString (== version))
		<* updateSequenceNumber Client
	fragmentUpdateHash $ contentToFragment c
	return c

decodeParams :: BS.ByteString -> Either String DH.Params
decodeParams = evalByteStringM $ do
	dhP <- byteStringToInteger <$> takeLen 2
	dhG <- byteStringToInteger <$> takeLen 2
	return (DH.Params dhP dhG)

decodePublicNumber :: BS.ByteString -> Either String DH.PublicNumber
decodePublicNumber = Right . fromInteger . byteStringToInteger
--	evalByteStringM $ fromInteger . byteStringToInteger <$> takeLen 2

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


class Base b where
	type Param b
	type Secret b
	type Public b
	generateBase :: CPRG g => g -> Param b -> (b, g)
	generateSecret :: CPRG g => g -> b -> (Secret b, g)
	calculatePublic :: b -> Secret b -> Public b
	calculateCommon :: b -> Secret b -> Public b -> BS.ByteString

	encodeBase :: b -> BS.ByteString
	decodeBase :: BS.ByteString -> b
	encodePublic :: b -> Public b -> BS.ByteString
	decodePublic :: b -> BS.ByteString -> Public b
