{-# LANGUAGE OverloadedStrings #-}

module Handshake (
	Parsable(..),
	Handshake(..),
	handshakeDoesServerHelloFinish, handshakeDoesFinish,
	handshakeDoesClientKeyExchange,
	handshakeClientRandom, handshakeServerRandom, handshakeCipherSuite,
	handshakeClientVersion, handshakeServerVersion,
	handshakeEncryptedPreMasterSecret,
	handshakeOnlyKnownCipherSuite,

	handshakeGetFinish,

	HandshakeType(HandshakeTypeFinished),
	handshakeCertificate, CertificateChain, handshakeSign,
	handshakeCertificateRequest,
	handshakeMakeVerify,
	handshakeMakeClientKeyExchange,

	ServerHello(..),
	ClientHello(..),
	CertificateRequest(..),
	ClientCertificateType(..),
	EncryptedPreMasterSecret(..),

	Random(..),
	CipherSuite(..),

	SignatureAlgorithm(..),
	HashAlgorithm(..),
	CompressionMethod(..),
	SessionId(..),
	Version(..),

	fst3, fromInt, headBS,
--	list1,
	whole, ByteStringM, evalByteStringM,

	ServerKeyExchange(..),
	verifyServerKeyExchange,
	integerToByteString,

	Extension(..),
	EcPointFormat(..),
	NamedCurve(..),
	secp256r1,
	encodePoint,
) where

import Prelude hiding (head, take, concat)

import Control.Applicative ((<$>))

import Data.Word
import qualified Data.ByteString as BS

import Hello
import Certificate
import KeyExchange
import Data.ByteString(ByteString, pack)
-- import ByteStringMonad
-- import ToByteString
-- import Parts

data Handshake
	= HandshakeClientHello ClientHello
	| HandshakeServerHello ServerHello
	| HandshakeCertificate CertificateChain
	| HandshakeServerKeyExchange ServerKeyExchange
	| HandshakeCertificateRequest CertificateRequest
	| HandshakeServerHelloDone
	| HandshakeCertificateVerify DigitallySigned
	| HandshakeClientKeyExchange EncryptedPreMasterSecret
	| HandshakeFinished ByteString
	| HandshakeRaw HandshakeType ByteString
	deriving Show

instance Parsable Handshake where
	parse = parseHandshake
	toByteString = handshakeToByteString
	listLength _ = Nothing

handshakeSign :: Handshake -> Maybe ByteString
handshakeSign (HandshakeCertificateVerify ds) = digitallySignedSign ds
handshakeSign _ = Nothing

handshakeMakeVerify ::
	HashAlgorithm -> SignatureAlgorithm -> ByteString -> Handshake
handshakeMakeVerify ha sa = HandshakeCertificateVerify . DigitallySigned (ha, sa)

handshakeCertificate :: Handshake -> Maybe CertificateChain
handshakeCertificate (HandshakeCertificate cc) = Just cc
handshakeCertificate _ = Nothing

handshakeClientRandom :: Handshake -> Maybe Random
handshakeClientRandom (HandshakeClientHello ch) = clientHelloClientRandom ch
handshakeClientRandom _ = Nothing

handshakeServerRandom :: Handshake -> Maybe Random
handshakeServerRandom (HandshakeServerHello sh) = serverHelloServerRandom sh
handshakeServerRandom _ = Nothing

handshakeClientVersion :: Handshake -> Maybe Version
handshakeClientVersion (HandshakeClientHello ch) = clientHelloClientVersion ch
handshakeClientVersion _ = Nothing

handshakeServerVersion :: Handshake -> Maybe Version
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

handshakeGetFinish :: Handshake -> Maybe ByteString
handshakeGetFinish (HandshakeFinished f) = Just f
handshakeGetFinish _ = Nothing

handshakeEncryptedPreMasterSecret :: Handshake -> Maybe EncryptedPreMasterSecret
handshakeEncryptedPreMasterSecret (HandshakeClientKeyExchange epms) = Just epms
handshakeEncryptedPreMasterSecret _ = Nothing

handshakeMakeClientKeyExchange :: EncryptedPreMasterSecret -> Handshake
handshakeMakeClientKeyExchange = HandshakeClientKeyExchange

parseHandshake :: ByteStringM Handshake
parseHandshake = do
	mt <- parseHandshakeType
	section 3 $ case mt of
		HandshakeTypeClientHello -> HandshakeClientHello <$> parse
		HandshakeTypeServerHello -> HandshakeServerHello <$> parse
		HandshakeTypeCertificate -> HandshakeCertificate <$> parse
		HandshakeTypeServerKeyExchange ->
			HandshakeServerKeyExchange <$> parse
		HandshakeTypeCertificateRequest ->
			HandshakeCertificateRequest <$> parse
		HandshakeTypeServerHelloDone ->
			const HandshakeServerHelloDone <$> whole
		HandshakeTypeCertificateVerify ->
			HandshakeCertificateVerify <$> parse
		HandshakeTypeClientKeyExchange ->
			HandshakeClientKeyExchange <$> parse
		HandshakeTypeFinished -> HandshakeFinished <$> whole
		_ -> HandshakeRaw mt <$> whole

handshakeToByteString :: Handshake -> ByteString
handshakeToByteString (HandshakeClientHello ch) = handshakeToByteString .
	HandshakeRaw HandshakeTypeClientHello $ toByteString ch
handshakeToByteString (HandshakeServerHello sh) = handshakeToByteString .
	HandshakeRaw HandshakeTypeServerHello $ toByteString sh
handshakeToByteString (HandshakeCertificate crts) = handshakeToByteString .
	HandshakeRaw HandshakeTypeCertificate $ toByteString crts
handshakeToByteString (HandshakeServerKeyExchange ske) = handshakeToByteString .
	HandshakeRaw HandshakeTypeServerKeyExchange $ toByteString ske
handshakeToByteString (HandshakeCertificateRequest cr) = handshakeToByteString .
	HandshakeRaw HandshakeTypeCertificateRequest $ toByteString cr
handshakeToByteString HandshakeServerHelloDone = handshakeToByteString $
	HandshakeRaw HandshakeTypeServerHelloDone ""
handshakeToByteString (HandshakeCertificateVerify ds) = handshakeToByteString .
	HandshakeRaw HandshakeTypeCertificateVerify $ toByteString ds
handshakeToByteString (HandshakeClientKeyExchange epms) = handshakeToByteString .
	HandshakeRaw HandshakeTypeClientKeyExchange $ toByteString epms
handshakeToByteString (HandshakeFinished bs) = handshakeToByteString $
	HandshakeRaw HandshakeTypeFinished bs
handshakeToByteString (HandshakeRaw mt bs) =
	handshakeTypeToByteString mt `BS.append` lenBodyToByteString 3 bs

data HandshakeType
	= HandshakeTypeClientHello
	| HandshakeTypeServerHello
	| HandshakeTypeCertificate
	| HandshakeTypeServerKeyExchange
	| HandshakeTypeCertificateRequest
	| HandshakeTypeServerHelloDone
	| HandshakeTypeCertificateVerify
	| HandshakeTypeClientKeyExchange
	| HandshakeTypeFinished
	| HandshakeTypeRaw Word8
	deriving Show

parseHandshakeType :: ByteStringM HandshakeType
parseHandshakeType = do
	ht <- headBS "9"
	return $ case ht of
		1 -> HandshakeTypeClientHello
		2 -> HandshakeTypeServerHello
		11 -> HandshakeTypeCertificate
		12 -> HandshakeTypeServerKeyExchange
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
handshakeTypeToByteString HandshakeTypeServerKeyExchange = pack [12]
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

handshakeCertificateRequest :: Handshake -> Maybe CertificateRequest
handshakeCertificateRequest (HandshakeCertificateRequest cr) = Just cr
handshakeCertificateRequest _ = Nothing
