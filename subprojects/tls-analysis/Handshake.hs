{-# LANGUAGE OverloadedStrings #-}

module Handshake (
	Handshake(..), parseHandshake, handshakeToByteString,
	handshakeDoesServerHelloFinish, handshakeDoesFinish,
	handshakeDoesClientKeyExchange,
	handshakeClientRandom, handshakeServerRandom, handshakeCipherSuite,
	handshakeClientVersion, handshakeServerVersion,
	handshakeEncryptedPreMasterSecret,
	handshakeOnlyKnownCipherSuite,

	HandshakeType(HandshakeTypeFinished),
	handshakeCertificate, CertificateChain, handshakeSign,

	ServerHello(..),
	CertificateRequest(..),
	ClientCertificateType(..),
	EncryptedPreMasterSecret(..),

	ProtocolVersion(..),
	Random(..),
	CipherSuite(..),

	SignatureAlgorithm(..),
	HashAlgorithm(..),
	CompressionMethod(..),
	SessionId(..),
	Version(..),

	fst3, fromInt,
) where

import Prelude hiding (head, take, concat)

import Control.Applicative ((<$>))
import Control.Monad

import Data.Word

import Hello
import Certificate
import DigitallySigned
import CertificateRequest
import PreMasterSecret
import Data.ByteString(ByteString, pack)
-- import ByteStringMonad
-- import ToByteString
-- import Parts

data Handshake
	= HandshakeClientHello ClientHello
	| HandshakeServerHello ServerHello
	| HandshakeCertificate CertificateChain
	| HandshakeCertificateRequest CertificateRequest
	| HandshakeServerHelloDone
	| HandshakeCertificateVerify DigitallySigned
	| HandshakeClientKeyExchange EncryptedPreMasterSecret
	| HandshakeFinished ByteString
	| HandshakeRaw HandshakeType ByteString
	deriving Show

handshakeSign :: Handshake -> Maybe ByteString
handshakeSign (HandshakeCertificateVerify ds) = digitallySignedSign ds
handshakeSign _ = Nothing

handshakeCertificate :: Handshake -> Maybe CertificateChain
handshakeCertificate (HandshakeCertificate cc) = Just cc
handshakeCertificate _ = Nothing

handshakeClientRandom :: Handshake -> Maybe Random
handshakeClientRandom (HandshakeClientHello ch) = clientHelloClientRandom ch
handshakeClientRandom _ = Nothing

handshakeServerRandom :: Handshake -> Maybe Random
handshakeServerRandom (HandshakeServerHello sh) = serverHelloServerRandom sh
handshakeServerRandom _ = Nothing

handshakeClientVersion :: Handshake -> Maybe ProtocolVersion
handshakeClientVersion (HandshakeClientHello ch) = clientHelloClientVersion ch
handshakeClientVersion _ = Nothing

handshakeServerVersion :: Handshake -> Maybe ProtocolVersion
handshakeServerVersion (HandshakeServerHello ch) = serverHelloServerVersion ch
handshakeServerVersion _ = Nothing

handshakeCipherSuite :: Handshake -> Maybe CipherSuite
handshakeCipherSuite (HandshakeServerHello sh) = serverHelloCipherSuite sh
handshakeCipherSuite _ = Nothing

handshakeDoesServerHelloFinish :: Handshake -> Bool
handshakeDoesServerHelloFinish HandshakeServerHelloDone = True
handshakeDoesServerHelloFinish (HandshakeRaw HandshakeTypeFinished _) = True
handshakeDoesServerHelloFinish _ = False

handshakeDoesClientKeyExchange :: Handshake -> Bool
handshakeDoesClientKeyExchange (HandshakeClientKeyExchange _) = True
handshakeDoesClientKeyExchange _ = False

handshakeDoesFinish :: Handshake -> Bool
handshakeDoesFinish (HandshakeRaw HandshakeTypeFinished _) = True
handshakeDoesFinish _ = False

handshakeEncryptedPreMasterSecret :: Handshake -> Maybe EncryptedPreMasterSecret
handshakeEncryptedPreMasterSecret (HandshakeClientKeyExchange epms) = Just epms
handshakeEncryptedPreMasterSecret _ = Nothing

parseHandshake :: ByteStringM Handshake
parseHandshake = do
	mt <- parseHandshakeType
	section 3 $ case mt of
		HandshakeTypeClientHello ->
			HandshakeClientHello <$> parseClientHello
		HandshakeTypeServerHello ->
			HandshakeServerHello <$> parseServerHello
		HandshakeTypeCertificate ->
			HandshakeCertificate <$> parseCertificateChain
		HandshakeTypeCertificateRequest ->
			HandshakeCertificateRequest <$> parseCertificateRequest
		HandshakeTypeServerHelloDone -> do
			e <- emptyBS
			unless e $ throwError "ServerHelloDone must empty"
			return HandshakeServerHelloDone
		HandshakeTypeCertificateVerify ->
			HandshakeCertificateVerify <$> parseDigitallySigned
		HandshakeTypeClientKeyExchange ->
			HandshakeClientKeyExchange <$> parseEncryptedPreMasterSecret
		HandshakeTypeFinished ->
			HandshakeFinished <$> whole
		_ -> HandshakeRaw mt <$> whole

handshakeToByteString :: Handshake -> ByteString
handshakeToByteString (HandshakeClientHello ch) = handshakeToByteString .
	HandshakeRaw HandshakeTypeClientHello $ clientHelloToByteString ch
handshakeToByteString (HandshakeServerHello sh) = handshakeToByteString .
	HandshakeRaw HandshakeTypeServerHello $ serverHelloToByteString sh
handshakeToByteString (HandshakeCertificate crts) = handshakeToByteString .
	HandshakeRaw HandshakeTypeCertificate $ certificateChainToByteString crts
handshakeToByteString (HandshakeCertificateRequest cr) = handshakeToByteString .
	HandshakeRaw HandshakeTypeCertificateRequest $
		certificateRequestToByteString cr
handshakeToByteString HandshakeServerHelloDone = handshakeToByteString $
	HandshakeRaw HandshakeTypeServerHelloDone ""
handshakeToByteString (HandshakeCertificateVerify ds) = handshakeToByteString .
	HandshakeRaw HandshakeTypeCertificateVerify $ digitallySignedToByteString ds
handshakeToByteString (HandshakeClientKeyExchange epms) = handshakeToByteString .
	HandshakeRaw HandshakeTypeClientKeyExchange $
		encryptedPreMasterSecretToByteString epms
handshakeToByteString (HandshakeFinished bs) = handshakeToByteString $
	HandshakeRaw HandshakeTypeFinished bs
handshakeToByteString (HandshakeRaw mt bs) =
	handshakeTypeToByteString mt `append` lenBodyToByteString 3 bs

data HandshakeType
	= HandshakeTypeClientHello
	| HandshakeTypeServerHello
	| HandshakeTypeCertificate
	| HandshakeTypeCertificateRequest
	| HandshakeTypeServerHelloDone
	| HandshakeTypeCertificateVerify
	| HandshakeTypeClientKeyExchange
	| HandshakeTypeFinished
	| HandshakeTypeRaw Word8
	deriving Show

parseHandshakeType :: ByteStringM HandshakeType
parseHandshakeType = do
	ht <- headBS
	return $ case ht of
		1 -> HandshakeTypeClientHello
		2 -> HandshakeTypeServerHello
		11 -> HandshakeTypeCertificate
		13 -> HandshakeTypeCertificateRequest
		14 -> HandshakeTypeServerHelloDone
		15 -> HandshakeTypeCertificateVerify
		16 -> HandshakeTypeClientKeyExchange
		20 -> HandshakeTypeFinished
		_ -> HandshakeTypeRaw ht

handshakeTypeToByteString :: HandshakeType -> ByteString
handshakeTypeToByteString HandshakeTypeClientHello = pack [1]
handshakeTypeToByteString HandshakeTypeServerHello = pack [2]
handshakeTypeToByteString HandshakeTypeCertificate = pack [11]
handshakeTypeToByteString HandshakeTypeCertificateRequest = pack [13]
handshakeTypeToByteString HandshakeTypeServerHelloDone = pack [14]
handshakeTypeToByteString HandshakeTypeCertificateVerify = pack [15]
handshakeTypeToByteString HandshakeTypeClientKeyExchange = pack [16]
handshakeTypeToByteString HandshakeTypeFinished = pack [20]
handshakeTypeToByteString (HandshakeTypeRaw w) = pack [w]

handshakeOnlyKnownCipherSuite :: Handshake -> Handshake
handshakeOnlyKnownCipherSuite (HandshakeClientHello ch) =
	HandshakeClientHello $ clientHelloOnlyKnownCipherSuite ch
handshakeOnlyKnownCipherSuite hs = hs
