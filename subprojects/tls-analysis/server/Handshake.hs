{-# LANGUAGE OverloadedStrings #-}

module Handshake (
	Handshake(..),
	ClientHello(..), ServerHello(..),
		SessionId(..),
		CipherSuite(..), KeyExchange(..), BulkEncryption(..),
		CompressionMethod(..),
	CertificateRequest(..),
		ClientCertificateType(..),
		SignatureAlgorithm(..), HashAlgorithm(..),
	ClientKeyExchange(..),
	DigitallySigned(..),
	NamedCurve(..),
) where

import Control.Applicative

import qualified Codec.Bytable as B

import Data.Word (Word8)
import Data.Word.Word24
import qualified Data.ByteString as BS

import Hello
--	(Bytable(..), ClientHello(..), ServerHello(..), takeLen', lenBodyToByteString)
import Certificate
import qualified Data.X509 as X509

data Handshake
	= HandshakeClientHello ClientHello
	| HandshakeServerHello ServerHello
	| HandshakeCertificate X509.CertificateChain
	| HandshakeServerKeyExchange BS.ByteString
	| HandshakeCertificateRequest CertificateRequest
	| HandshakeServerHelloDone
	| HandshakeCertificateVerify DigitallySigned
	| HandshakeClientKeyExchange ClientKeyExchange
	| HandshakeFinished BS.ByteString
	| HandshakeRaw HandshakeType BS.ByteString
	deriving Show

instance B.Bytable Handshake where
	fromByteString = B.evalBytableM B.parse
	toByteString = handshakeToByteString

instance B.Parsable Handshake where
	parse = parseHandshake

parseHandshake :: B.BytableM Handshake
parseHandshake = do
	t <- B.take 1
	len <- B.take 3
	case t of
		HandshakeTypeClientHello -> HandshakeClientHello <$> B.take len
		HandshakeTypeServerHello -> HandshakeServerHello <$> B.take len
		HandshakeTypeCertificate -> HandshakeCertificate <$> B.take len
		HandshakeTypeServerKeyExchange ->
			HandshakeServerKeyExchange <$> B.take len
		HandshakeTypeCertificateRequest ->
			HandshakeCertificateRequest <$> B.take len
		HandshakeTypeServerHelloDone -> return HandshakeServerHelloDone
		HandshakeTypeCertificateVerify ->
			HandshakeCertificateVerify <$> B.take len
		HandshakeTypeClientKeyExchange ->
			HandshakeClientKeyExchange <$> B.take len
		HandshakeTypeFinished -> HandshakeFinished <$> B.take len
		_ -> HandshakeRaw t <$> B.take len

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
