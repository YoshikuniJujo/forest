{-# LANGUAGE PackageImports, OverloadedStrings, TupleSections,
	RankNTypes #-}
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
	CipherSuite(..), KeyExchange(..), BulkEncryption(..),
) where

import Prelude hiding (read)

import Control.Applicative
import "monads-tf" Control.Monad.Error
import "monads-tf" Control.Monad.Error.Class
import "monads-tf" Control.Monad.State
import Data.Word
import qualified Data.ByteString as BS
import "crypto-random" Crypto.Random
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA

import HM

import qualified CryptoTools as CT
import CipherSuite

import Data.HandleLike

decryptRSA :: (HandleLike h, CPRG gen) =>
	RSA.PrivateKey -> BS.ByteString -> HandshakeM h gen BS.ByteString
decryptRSA pk e = do
	tlss@TlsState{ tlssRandomGen = gen } <- get
	let (ret, gen') = RSA.decryptSafer gen pk e
	put tlss{ tlssRandomGen = gen' }
	case ret of
		Right d -> return d
		Left err -> throwError . strMsg $ show err

generateKeys :: HandleLike h => BS.ByteString -> HandshakeM h gen ()
generateKeys pms = do
	tlss@TlsState{
		tlssCachedCipherSuite = cs,
		tlssClientRandom = mcr,
		tlssServerRandom = msr } <- get
	mkl <- case cs of
		Just (CipherSuite _ AES_128_CBC_SHA) -> return 20
		Just (CipherSuite _ AES_128_CBC_SHA256) -> return 32
		_ -> throwError "generateKeys: not implemented"
	case (CT.ClientRandom <$> mcr, CT.ServerRandom <$> msr) of
		(Just cr, Just sr) -> do
			let	ms = CT.generateMasterSecret pms cr sr
				ems = CT.generateKeyBlock cr sr ms $
					mkl * 2 + 32
				[cwmk, swmk, cwk, swk] = divide [mkl, mkl, 16, 16] ems
			put $ tlss {
				tlssMasterSecret = Just ms,
				tlssClientWriteMacKey = Just cwmk,
				tlssServerWriteMacKey = Just swmk,
				tlssClientWriteKey = Just cwk,
				tlssServerWriteKey = Just swk }
		_ -> throwError "No client random / No server random"
	where
	divide [] _ = []
	divide (n : ns) bs
		| bs == BS.empty = []
		| otherwise = let (x, xs) = BS.splitAt n bs in x : divide ns xs

finishedHash :: HandleLike h => Partner -> HandshakeM h gen BS.ByteString
finishedHash partner = do
	mms <- gets tlssMasterSecret
	sha256 <- handshakeHash
	case mms of
		Just ms -> return $
			CT.generateFinished CT.TLS12 (partner == Client) ms sha256
		_ -> throwError "No master secrets"

tlsEncryptMessage :: (HandleLike h, CPRG gen) =>
	CT.ContentType -> (Word8, Word8) -> BS.ByteString -> HandshakeM h gen BS.ByteString
tlsEncryptMessage ct v msg = do
	cs <- cipherSuite Server
	mwk <- writeKey Server
	sn <- sequenceNumber Server
	updateSequenceNumber Server
	mmk <- macKey Server
	gen <- gets tlssRandomGen
	mhs <- case cs of
		CipherSuite _ AES_128_CBC_SHA -> return $ Just CT.hashSha1
		CipherSuite _ AES_128_CBC_SHA256 -> return $ Just CT.hashSha256
		CipherSuite KE_NULL BE_NULL -> return Nothing
		_ -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionIllegalParameter
			"HandshakeM.tlsEncryptMessage: not implemented cipher suite"
	case (mhs, mwk, mmk) of
		(Just hs, Just wk, Just mk)
			-> do	let (ret, gen') =
					CT.encryptMessage hs gen wk sn mk ct v msg
				tlss <- get
				put tlss{ tlssRandomGen = gen' }
				return ret
		(Nothing, _, _) -> return msg
		(_, Nothing, _) -> throwError "encryptMessage: No key"
		(_, _, Nothing) -> throwError "encryptMessage: No MAC key"

tlsDecryptMessage :: HandleLike h =>
	CT.ContentType -> (Word8, Word8) -> BS.ByteString -> HandshakeM h gen BS.ByteString
tlsDecryptMessage ct v enc = do
	cs <- cipherSuite Client
	mwk <- writeKey Client
	sn <- sequenceNumber Client
	mmk <- macKey Client
	case (cs, mwk, mmk) of
		(CipherSuite _ AES_128_CBC_SHA, Just key, Just mk)
			-> do	let emsg = CT.decryptMessage CT.hashSha1 key sn mk ct v enc
				case emsg of
					Right msg -> return msg
					Left err -> throwError $ Alert
						AlertLevelFatal
						AlertDescriptionBadRecordMac
						err
		(CipherSuite _ AES_128_CBC_SHA256, Just key, Just mk)
			-> do	let emsg = CT.decryptMessage CT.hashSha256 key sn mk ct v enc
				case emsg of
					Right msg -> return msg
					Left err -> throwError $ Alert
						AlertLevelFatal
						AlertDescriptionBadRecordMac
						err
		(CipherSuite KE_NULL BE_NULL, _, _) -> return enc
		_ -> throwError "HandshakeM.tlsDecryptMessage: No keys or bad cipher suite"
