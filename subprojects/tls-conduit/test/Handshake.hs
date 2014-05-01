{-# LANGUAGE OverloadedStrings, TupleSections #-}

module Handshake (
	Handshake,
	HandshakeType(..),
	handshakeList,
	handshakeOne,
	handshakeToHandshakeType,
	handshakeToByteString,
	takeEncryptedPreMasterSecret,
	takeClientHello,
	takeServerHello
) where

import Control.Applicative

import Data.Word
import qualified Data.ByteString as BS

import ClientHello
import ServerHello
import Certificate
import PreMasterSecret
-- import Parts
import Tools

handshakeList :: BS.ByteString -> Either String [Handshake]
handshakeList "" = return []
handshakeList src = do
	(h, rest) <- handshakeOne src
	hs <- handshakeList rest
	return (h : hs)

handshakeOne :: BS.ByteString -> Either String (Handshake, BS.ByteString)
handshakeOne src = do
	(ht, rest) <- eitherUncons src
	(bslen, rest') <- eitherSplitAt "get len" 3 rest
	len <- toLen bslen
	(body, rest'') <- eitherSplitAt
		("get body: " ++ show bslen ++ "(" ++ show len ++ ")") len rest'
	(, rest'') <$> handshake (handshakeType ht) body

handshakeToByteString :: Handshake -> BS.ByteString
handshakeToByteString (HandshakeClientHello body) = handshakeToByteString $
	HandshakeRaw HandshakeTypeClientHello $ clientHelloToByteString body
handshakeToByteString (HandshakeServerHello body) = handshakeToByteString $
	HandshakeRaw HandshakeTypeServerHello $ serverHelloToByteString body
handshakeToByteString (HandshakeCertificate body) = handshakeToByteString $
	HandshakeRaw HandshakeTypeCertificate $
		certificateChainToByteString body
handshakeToByteString (HandshakeServerHelloDone body) = handshakeToByteString $
	HandshakeRaw HandshakeTypeServerHelloDone body
handshakeToByteString (HandshakeClientKeyExchange epms) = handshakeToByteString $
	HandshakeRaw HandshakeTypeClientKeyExchange $
		encryptedPreMasterSecretToByteString epms
handshakeToByteString (HandshakeRaw ht body) =
	handshakeTypeToByteString ht `BS.append`
	fromLen 3 (BS.length body) `BS.append`
	body

data Handshake
	= HandshakeClientHello ClientHello
	| HandshakeServerHello ServerHello
	| HandshakeCertificate CertificateChain
	| HandshakeServerHelloDone BS.ByteString
	| HandshakeClientKeyExchange EncryptedPreMasterSecret
	| HandshakeRaw HandshakeType BS.ByteString
	deriving Show

handshake :: HandshakeType -> BS.ByteString -> Either String Handshake
handshake HandshakeTypeClientHello body =
	HandshakeClientHello <$> parseClientHello body
handshake HandshakeTypeServerHello body = HandshakeServerHello <$> serverHello body
handshake HandshakeTypeCertificate body =
	HandshakeCertificate . fst <$> certificateChain body
handshake HandshakeTypeServerHelloDone body = return $ HandshakeServerHelloDone body
handshake HandshakeTypeClientKeyExchange body = HandshakeClientKeyExchange . fst <$>
	encryptedPreMasterSecret body
handshake ht body = return $ HandshakeRaw ht body

handshakeToHandshakeType :: Handshake -> HandshakeType
handshakeToHandshakeType (HandshakeClientHello _) = HandshakeTypeClientHello
handshakeToHandshakeType (HandshakeServerHello _) = HandshakeTypeServerHello
handshakeToHandshakeType (HandshakeCertificate _) = HandshakeTypeCertificate
handshakeToHandshakeType (HandshakeServerHelloDone _) = HandshakeTypeServerHelloDone
handshakeToHandshakeType (HandshakeClientKeyExchange _) =
	HandshakeTypeClientKeyExchange
handshakeToHandshakeType (HandshakeRaw ht _) = ht

data HandshakeType
	= HandshakeTypeClientHello
	| HandshakeTypeServerHello
	| HandshakeTypeCertificate
	| HandshakeTypeServerKeyExchange
	| HandshakeTypeServerHelloDone
	| HandshakeTypeClientKeyExchange
	| HandshakeTypeFinished
	| HandshakeTypeRaw Word8
	deriving (Show, Eq)

handshakeType :: Word8 -> HandshakeType
handshakeType 1 = HandshakeTypeClientHello
handshakeType 2 = HandshakeTypeServerHello
handshakeType 11 = HandshakeTypeCertificate
handshakeType 12 = HandshakeTypeServerKeyExchange
handshakeType 14 = HandshakeTypeServerHelloDone
handshakeType 16 = HandshakeTypeClientKeyExchange
handshakeType 20 = HandshakeTypeFinished
handshakeType w = HandshakeTypeRaw w

handshakeTypeToByteString :: HandshakeType -> BS.ByteString
handshakeTypeToByteString HandshakeTypeClientHello = "\x01"
handshakeTypeToByteString HandshakeTypeServerHello = "\x02"
handshakeTypeToByteString HandshakeTypeCertificate = "\x0b"
handshakeTypeToByteString HandshakeTypeServerKeyExchange = "\x0c"
handshakeTypeToByteString HandshakeTypeServerHelloDone = "\x0e"
handshakeTypeToByteString HandshakeTypeClientKeyExchange = "\x10"
handshakeTypeToByteString HandshakeTypeFinished = "\x14"
handshakeTypeToByteString (HandshakeTypeRaw w) = BS.pack [w]

takeEncryptedPreMasterSecret :: Handshake -> Maybe EncryptedPreMasterSecret
takeEncryptedPreMasterSecret (HandshakeClientKeyExchange epms) = Just epms
takeEncryptedPreMasterSecret _ = Nothing

takeClientHello :: Handshake -> Maybe ClientHello
takeClientHello (HandshakeClientHello ch) = Just ch
takeClientHello _ = Nothing

takeServerHello :: Handshake -> Maybe ServerHello
takeServerHello (HandshakeServerHello sh) = Just sh
takeServerHello _ = Nothing
