{-# LANGUAGE OverloadedStrings, PackageImports, TypeFamilies #-}

module Base (
	sendServerKeyExchange,
	clientKeyExchange,
	Base(..),
) where

import Control.Applicative
import Data.Maybe
import qualified Data.ByteString as BS
import "crypto-random" Crypto.Random
import qualified Crypto.PubKey.RSA as RSA

import Fragment
import Types
import KeyExchange
import Content

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

version :: Version
version = Version 3 3
	
sendServerKeyExchange ::
	Base b => b -> Secret b -> RSA.PrivateKey -> BS.ByteString -> TlsIo ()
sendServerKeyExchange ps dhsk pk sr = do
	Just cr <- getClientRandom
	let	ske = HandshakeServerKeyExchange . addSign pk cr sr $
			ServerKeyExchange
				(encodeBase ps)
				(encodePublic ps $ calculatePublic ps dhsk)
				2 1 "hogeru"
	((>>) <$> writeFragment <*> fragmentUpdateHash) . contentListToFragment .
		map (ContentHandshake version) $ catMaybes [
		Just ske
	 ]

clientKeyExchange :: Base b => b -> Secret b -> Version -> TlsIo ()
clientKeyExchange dhps dhpn (Version _cvmjr _cvmnr) = do
	hs <- readHandshake (== version)
	case hs of
		HandshakeClientKeyExchange (EncryptedPreMasterSecret epms) -> do
			liftIO . putStrLn $ "CLIENT KEY: " ++ show epms
			let pms = calculateCommon dhps dhpn $ decodePublic dhps epms
			generateKeys pms
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
