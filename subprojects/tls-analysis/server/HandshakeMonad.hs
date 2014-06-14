{-# LANGUAGE PackageImports, OverloadedStrings, TupleSections,
	RankNTypes, FlexibleContexts #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module HandshakeMonad (
	HandshakeM, TlsState(..), liftIO, throwError, catchError,
	randomByteString,
	Partner(..), runHandshakeM, initTlsState,

	setClientRandom, setServerRandom,
	setVersion,
	getClientRandom, getServerRandom, getCipherSuite,
	cacheCipherSuite, flushCipherSuite,

	decryptRSA, generateKeys, updateHash, finishedHash,
	handshakeHash,

	tlsEncryptMessage, tlsDecryptMessage,
	updateSequenceNumber,

	buffered, getContentType,
	Alert(..), AlertLevel(..), AlertDescription(..), alertVersion, processAlert,
	alertToByteString,
	CT.MSVersion(..),
	CT.decryptMessage, CT.hashSha1, CT.hashSha256,
	CT.encryptMessage,

	withRandom,
	getHandle,

	write,
	read,

	CT.ContentType(..),
	CT.CipherSuite(..), CT.KeyExchange(..), CT.BulkEncryption(..),
) where

import Prelude hiding (read)

import "monads-tf" Control.Monad.Error
import "monads-tf" Control.Monad.Error.Class
import "monads-tf" Control.Monad.State
import qualified Data.ByteString as BS
import "crypto-random" Crypto.Random
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA

import HM

import qualified CryptoTools as CT

import Data.HandleLike

decryptRSA :: (HandleLike h, CPRG gen) =>
	RSA.PrivateKey -> BS.ByteString -> HandshakeM h gen BS.ByteString
decryptRSA pk e = eitherToError =<< withRandom (\gen -> RSA.decryptSafer gen pk e)

generateKeys :: HandleLike h => BS.ByteString -> HandshakeM h gen ()
generateKeys pms = do
	Just (CT.CipherSuite _ be) <- getCipherSuite
	(cr, sr) <- getRandoms
	either (throwError . strMsg) saveKeys $ CT.generateKeys_ be cr sr pms

finishedHash :: HandleLike h => Partner -> HandshakeM h gen BS.ByteString
finishedHash partner = do
	Just ms <- gets tlssMasterSecret
	sha256 <- handshakeHash
	return $ CT.finishedHash_ (partner == Client) ms sha256

tlsEncryptMessage :: (HandleLike h, CPRG gen) =>
	CT.ContentType -> BS.ByteString -> HandshakeM h gen BS.ByteString
tlsEncryptMessage ct msg = ifEnc Server msg $ \m -> do
	CT.CipherSuite _ be <- cipherSuite Server
	(wk, mk, sn) <- getServerWrite
	enc <- case CT.tlsEncryptMessage__ be ct wk mk sn m of
		Left e -> throwError $ strMsg e
		Right e -> return e
	withRandom enc

tlsDecryptMessage :: HandleLike h =>
	CT.ContentType -> BS.ByteString -> HandshakeM h gen BS.ByteString
tlsDecryptMessage ct enc = ifEnc Client enc $ \e -> do
	CT.CipherSuite _ be <- cipherSuite Client
	(wk, mk, sn) <- getClientWrite
	case CT.tlsDecryptMessage__ be ct wk mk sn e of
		Left err -> throwError $ strMsg err
		Right m -> return m
