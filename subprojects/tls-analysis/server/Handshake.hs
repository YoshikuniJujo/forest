{-# LANGUAGE OverloadedStrings #-}

module Handshake (
	Handshake(..), takeHandshake, handshakeToByteString,
	ContentType(..), Bytable(..),

	ClientHello(..), ServerHello(..),
		Version(..), Random(..), SessionId(..),
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
import qualified Data.ByteString as BS

import Hello
--	(Bytable(..), ClientHello(..), ServerHello(..), takeLen', lenBodyToByteString)
import Certificate

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
	mt <- (either error id . fromByteString) `liftM` rd 1
	bs <- takeLen' rd 3
	return $ case mt of
		HandshakeTypeClientHello -> HandshakeClientHello .
			either error id $ B.fromByteString bs
		HandshakeTypeServerHello -> HandshakeServerHello .
			either error id $ fromByteString bs
		HandshakeTypeCertificate -> HandshakeCertificate .
			either error id $ fromByteString bs
		HandshakeTypeServerKeyExchange -> HandshakeServerKeyExchange bs
		HandshakeTypeCertificateRequest -> HandshakeCertificateRequest .
			either error id $ fromByteString bs
		HandshakeTypeServerHelloDone -> HandshakeServerHelloDone
		HandshakeTypeCertificateVerify -> HandshakeCertificateVerify .
			either error id $ fromByteString bs
		HandshakeTypeClientKeyExchange -> HandshakeClientKeyExchange .
			either error id $ fromByteString bs
		HandshakeTypeFinished -> HandshakeFinished bs
		_ -> HandshakeRaw mt bs

handshakeToByteString :: Handshake -> BS.ByteString
handshakeToByteString (HandshakeClientHello ch) = handshakeToByteString .
	HandshakeRaw HandshakeTypeClientHello $ B.toByteString ch
handshakeToByteString (HandshakeServerHello sh) = handshakeToByteString .
	HandshakeRaw HandshakeTypeServerHello $ toByteString_ sh
handshakeToByteString (HandshakeCertificate crts) = handshakeToByteString .
	HandshakeRaw HandshakeTypeCertificate $ toByteString_ crts
handshakeToByteString (HandshakeServerKeyExchange ske) = handshakeToByteString $
	HandshakeRaw HandshakeTypeServerKeyExchange ske
handshakeToByteString (HandshakeCertificateRequest cr) = handshakeToByteString .
	HandshakeRaw HandshakeTypeCertificateRequest $ toByteString_ cr
handshakeToByteString HandshakeServerHelloDone = handshakeToByteString $
	HandshakeRaw HandshakeTypeServerHelloDone ""
handshakeToByteString (HandshakeCertificateVerify ds) = handshakeToByteString .
	HandshakeRaw HandshakeTypeCertificateVerify $ toByteString_ ds
handshakeToByteString (HandshakeClientKeyExchange epms) = handshakeToByteString .
	HandshakeRaw HandshakeTypeClientKeyExchange $ toByteString_ epms
handshakeToByteString (HandshakeFinished bs) = handshakeToByteString $
	HandshakeRaw HandshakeTypeFinished bs
handshakeToByteString (HandshakeRaw mt bs) =
	toByteString_ mt `BS.append` lenBodyToByteString 3 bs

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

instance Bytable HandshakeType where
	fromByteString = byteStringToHandshakeType
	toByteString_ = handshakeTypeToByteString

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
