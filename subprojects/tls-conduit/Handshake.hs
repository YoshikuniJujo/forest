{-# LANGUAGE OverloadedStrings #-}

module Handshake (Handshake(..), parseHandshake, handshakeToByteString) where

import Prelude hiding (head, take, concat)

import Control.Applicative ((<$>))
import Control.Monad

import Data.Word

import ClientHello
import ServerHello
import Certificate
import PreMasterSecret
import ByteStringMonad
import ToByteString

data Handshake
	= HandshakeClientHello ClientHello
	| HandshakeServerHello ServerHello
	| HandshakeCertificate CertificateChain
	| HandshakeServerHelloDone
	| HandshakeClientKeyExchange EncryptedPreMasterSecret
	| HandshakeRaw HandshakeType ByteString
	deriving Show

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
		HandshakeTypeServerHelloDone -> do
			e <- empty
			when (not e) $ throwError "ServerHelloDone must empty"
			return HandshakeServerHelloDone
		HandshakeTypeClientKeyExchange ->
			HandshakeClientKeyExchange <$> parseEncryptedPreMasterSecret
		_ -> HandshakeRaw mt <$> whole

handshakeToByteString :: Handshake -> ByteString
handshakeToByteString (HandshakeClientHello ch) = handshakeToByteString $
	HandshakeRaw HandshakeTypeClientHello $ clientHelloToByteString ch
handshakeToByteString (HandshakeServerHello sh) = handshakeToByteString $
	HandshakeRaw HandshakeTypeServerHello $ serverHelloToByteString sh
handshakeToByteString (HandshakeCertificate crts) = handshakeToByteString $
	HandshakeRaw HandshakeTypeCertificate $ certificateChainToByteString crts
handshakeToByteString HandshakeServerHelloDone = handshakeToByteString $
	HandshakeRaw HandshakeTypeServerHelloDone ""
handshakeToByteString (HandshakeClientKeyExchange epms) = handshakeToByteString $
	HandshakeRaw HandshakeTypeClientKeyExchange $
		encryptedPreMasterSecretToByteString epms
handshakeToByteString (HandshakeRaw mt bs) =
	handshakeTypeToByteString mt `append` lenBodyToByteString 3 bs

data HandshakeType
	= HandshakeTypeClientHello
	| HandshakeTypeServerHello
	| HandshakeTypeCertificate
	| HandshakeTypeServerHelloDone
	| HandshakeTypeClientKeyExchange
	| HandshakeTypeRaw Word8
	deriving Show

parseHandshakeType :: ByteStringM HandshakeType
parseHandshakeType = do
	ht <- head
	return $ case ht of
		1 -> HandshakeTypeClientHello
		2 -> HandshakeTypeServerHello
		11 -> HandshakeTypeCertificate
		14 -> HandshakeTypeServerHelloDone
		16 -> HandshakeTypeClientKeyExchange
		_ -> HandshakeTypeRaw ht

handshakeTypeToByteString :: HandshakeType -> ByteString
handshakeTypeToByteString HandshakeTypeClientHello = pack [1]
handshakeTypeToByteString HandshakeTypeServerHello = pack [2]
handshakeTypeToByteString HandshakeTypeCertificate = pack [11]
handshakeTypeToByteString HandshakeTypeServerHelloDone = pack [14]
handshakeTypeToByteString HandshakeTypeClientKeyExchange = pack [16]
handshakeTypeToByteString (HandshakeTypeRaw w) = pack [w]
