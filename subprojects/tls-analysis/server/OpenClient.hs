{-# LANGUAGE PackageImports, OverloadedStrings, TupleSections, TypeFamilies #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module OpenClient (
	ContentType(..),
	HandshakeM, liftIO, throwError, catchError,
	randomByteString,
	Partner(..),

	flushCipherSuite,

	generateKeys_,
	finishedHash_,

	updateHash,
	handshakeHash,

	TlsClient(..),
	TlsClientConst,
	TlsClientState,
	runOpen,
	initialTlsState,

	buffered, getContentType,
	Alert(..), AlertLevel(..), AlertDescription(..),
	checkName, clientName,

	withRandom,
	getHandle,

	write,
	read,
	debugCipherSuite,

	cipherSuite,
	updateSequenceNumber,
	encryptMessage,
	decryptMessage,
	CipherSuite(..),
	BulkEncryption(..),

	hashSha1,
	hashSha256,
	TlsHandle,
	mkTlsHandle,
	Keys(..), nullKeys,
) where

import Prelude hiding (read)

import "monads-tf" Control.Monad.Error
import "crypto-random" Crypto.Random

import Data.HandleLike

import HM

import "monads-tf" Control.Monad.State

import OC

runOpen :: (HandleLike h, CPRG gen) => h ->
	HandshakeM h gen ([String], Keys) ->
	HandleMonad (TlsClientConst h gen) (TlsClientConst h gen)
runOpen cl opn = StateT $ \s -> runOpenSt_ s cl opn

runOpenSt_ :: (HandleLike h, CPRG gen) => TlsClientState gen ->
	h -> HandshakeM h gen ([String], Keys) ->
	HandleMonad h (TlsClientConst h gen, TlsClientState gen)
runOpenSt_ s cl opn = do
	let	(cid, s') = newClientId s
	((ns, ks), tlss) <- runHandshakeM (mkTlsHandle cl) opn $
		initHandshakeState (getRandomGenSt s')
	let	s'' = setRandomGen (randomGen tlss) s'
		tc = TlsClientConst {
			clientId = cid,
			tlsNames = ns,
			tlsCipherSuite = cipherSuite Client ks,
			tlsHandle = cl,
			tlsClientWriteMacKey = kClientWriteMacKey ks,
			tlsServerWriteMacKey = kServerWriteMacKey ks,
			tlsClientWriteKey = kClientWriteKey ks,
			tlsServerWriteKey = kServerWriteKey ks }
	return (tc, s'')
