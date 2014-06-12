{-# LANGUAGE OverloadedStrings #-}

module Handshake (
	Handshake(..), takeHandshake, handshakeToByteString,

	ClientHello(..), ServerHello(..),
		-- Version(..), -- Random(..),
		SessionId(..),
		CipherSuite(..), CipherSuiteKeyEx(..), CipherSuiteMsgEnc(..),
		CompressionMethod(..),
	CertificateRequest(..),
		ClientCertificateType(..),
		SignatureAlgorithm(..), HashAlgorithm(..),
	EncryptedPreMasterSecret(..),
	DigitallySigned(..),
) where

import qualified Codec.Bytable as B

import Control.Monad (liftM)
import Data.Word (Word8)
import Data.Word.Word24
import qualified Data.ByteString as BS

import Hello
--	(Bytable(..), ClientHello(..), ServerHello(..), takeLen', lenBodyToByteString)
import Certificate

takeInt :: Monad m => (Int -> m BS.ByteString) -> Int -> m Int
takeInt rd = ((either error id . B.fromByteString) `liftM`) . rd

takeLen :: Monad m => (Int -> m BS.ByteString) -> Int -> m BS.ByteString
takeLen rd n = do
	l <- takeInt rd n
	rd l

data Handshake
	= HandshakeClientHello ClientHello
	| HandshakeServerHello ServerHello
	| HandshakeCertificate CertificateChain
	| HandshakeServerKeyExchange BS.ByteString
	| HandshakeCertificateRequest CertificateRequest
	| HandshakeServerHelloDone
	| HandshakeCertificateVerify DigitallySigned
	| HandshakeClientKeyExchange EncryptedPreMasterSecret
	| HandshakeFinished BS.ByteString
	| HandshakeRaw HandshakeType BS.ByteString
	deriving Show

takeHandshake :: Monad m => (Int -> m BS.ByteString) -> m Handshake
takeHandshake rd = do
	mt <- (either error id . B.fromByteString) `liftM` rd 1
	bs <- takeLen rd 3
	return $ case mt of
		HandshakeTypeClientHello -> HandshakeClientHello .
			either error id $ B.fromByteString bs
		HandshakeTypeServerHello -> HandshakeServerHello .
			either error id $ B.fromByteString bs
		HandshakeTypeCertificate -> HandshakeCertificate .
			either error id $ B.fromByteString bs
		HandshakeTypeServerKeyExchange -> HandshakeServerKeyExchange bs
		HandshakeTypeCertificateRequest -> HandshakeCertificateRequest .
			either error id $ B.fromByteString bs
		HandshakeTypeServerHelloDone -> HandshakeServerHelloDone
		HandshakeTypeCertificateVerify -> HandshakeCertificateVerify .
			either error id $ B.fromByteString bs
		HandshakeTypeClientKeyExchange -> HandshakeClientKeyExchange .
			either error id $ B.fromByteString bs
		HandshakeTypeFinished -> HandshakeFinished bs
		_ -> HandshakeRaw mt bs

handshakeToByteString :: Handshake -> BS.ByteString
handshakeToByteString (HandshakeClientHello ch) = handshakeToByteString .
	HandshakeRaw HandshakeTypeClientHello $ B.toByteString ch
handshakeToByteString (HandshakeServerHello sh) = handshakeToByteString .
	HandshakeRaw HandshakeTypeServerHello $ B.toByteString sh
handshakeToByteString (HandshakeCertificate crts) = handshakeToByteString .
	HandshakeRaw HandshakeTypeCertificate $ B.toByteString crts
handshakeToByteString (HandshakeServerKeyExchange ske) = handshakeToByteString $
	HandshakeRaw HandshakeTypeServerKeyExchange ske
handshakeToByteString (HandshakeCertificateRequest cr) = handshakeToByteString .
	HandshakeRaw HandshakeTypeCertificateRequest $ B.toByteString cr
handshakeToByteString HandshakeServerHelloDone = handshakeToByteString $
	HandshakeRaw HandshakeTypeServerHelloDone ""
handshakeToByteString (HandshakeCertificateVerify ds) = handshakeToByteString .
	HandshakeRaw HandshakeTypeCertificateVerify $ B.toByteString ds
handshakeToByteString (HandshakeClientKeyExchange epms) = handshakeToByteString .
	HandshakeRaw HandshakeTypeClientKeyExchange $ B.toByteString epms
handshakeToByteString (HandshakeFinished bs) = handshakeToByteString $
	HandshakeRaw HandshakeTypeFinished bs
handshakeToByteString (HandshakeRaw mt bs) =
	B.toByteString mt `BS.append` B.addLength (undefined :: Word24) bs

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

instance B.Bytable HandshakeType where
	fromByteString = byteStringToHandshakeType
	toByteString = handshakeTypeToByteString

byteStringToHandshakeType :: BS.ByteString -> Either String HandshakeType
byteStringToHandshakeType bs = case BS.unpack bs of
	[1] -> Right HandshakeTypeClientHello
	[2] -> Right HandshakeTypeServerHello
	[11] -> Right HandshakeTypeCertificate
	[12] -> Right HandshakeTypeServerKeyExchange
	[13] -> Right HandshakeTypeCertificateRequest
	[14] -> Right HandshakeTypeServerHelloDone
	[15] -> Right HandshakeTypeCertificateVerify
	[16] -> Right HandshakeTypeClientKeyExchange
	[20] -> Right HandshakeTypeFinished
	[ht] -> Right $ HandshakeTypeRaw ht
	_ -> Left "Handshake.byteStringToHandshakeType"

handshakeTypeToByteString :: HandshakeType -> BS.ByteString
handshakeTypeToByteString HandshakeTypeClientHello = BS.pack [1]
handshakeTypeToByteString HandshakeTypeServerHello = BS.pack [2]
handshakeTypeToByteString HandshakeTypeCertificate = BS.pack [11]
handshakeTypeToByteString HandshakeTypeServerKeyExchange = BS.pack [12]
handshakeTypeToByteString HandshakeTypeCertificateRequest = BS.pack [13]
handshakeTypeToByteString HandshakeTypeServerHelloDone = BS.pack [14]
handshakeTypeToByteString HandshakeTypeCertificateVerify = BS.pack [15]
handshakeTypeToByteString HandshakeTypeClientKeyExchange = BS.pack [16]
handshakeTypeToByteString HandshakeTypeFinished = BS.pack [20]
handshakeTypeToByteString (HandshakeTypeRaw w) = BS.pack [w]
