module Handshake (Handshake, parseHandshake, handshakeToByteString) where

import Prelude hiding (head, take, concat)

import Control.Applicative ((<$>))

import Data.Word

import ClientHello
import ServerHello
import Certificate
import ByteStringMonad
import ToByteString

data Handshake
	= HandshakeClientHello ClientHello
	| HandshakeServerHello ServerHello
	| HandshakeCertificate CertificateChain
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
		_ -> HandshakeRaw mt <$> whole

handshakeToByteString :: Handshake -> ByteString
handshakeToByteString (HandshakeClientHello ch) = handshakeToByteString $
	HandshakeRaw HandshakeTypeClientHello $ clientHelloToByteString ch
handshakeToByteString (HandshakeServerHello sh) = handshakeToByteString $
	HandshakeRaw HandshakeTypeServerHello $ serverHelloToByteString sh
handshakeToByteString (HandshakeCertificate crts) = handshakeToByteString $
	HandshakeRaw HandshakeTypeCertificate $ certificateChainToByteString crts
handshakeToByteString (HandshakeRaw mt bs) =
	handshakeTypeToByteString mt `append` lenBodyToByteString 3 bs

data HandshakeType
	= HandshakeTypeClientHello
	| HandshakeTypeServerHello
	| HandshakeTypeCertificate
	| HandshakeTypeRaw Word8
	deriving Show

parseHandshakeType :: ByteStringM HandshakeType
parseHandshakeType = do
	ht <- head
	return $ case ht of
		1 -> HandshakeTypeClientHello
		2 -> HandshakeTypeServerHello
		11 -> HandshakeTypeCertificate
		_ -> HandshakeTypeRaw ht

handshakeTypeToByteString :: HandshakeType -> ByteString
handshakeTypeToByteString HandshakeTypeClientHello = pack [1]
handshakeTypeToByteString HandshakeTypeServerHello = pack [2]
handshakeTypeToByteString HandshakeTypeCertificate = pack [11]
handshakeTypeToByteString (HandshakeTypeRaw w) = pack [w]
