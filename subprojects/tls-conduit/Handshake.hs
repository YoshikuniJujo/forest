{-# LANGUAGE OverloadedStrings #-}

module Handshake (
	Handshake,
	HandshakeType(..),
	handshakeList,
	handshakeToHandshakeType,
	handshakeToByteString
) where

import Data.Word
import qualified Data.ByteString as BS

import Tools

handshakeList :: BS.ByteString -> Maybe [Handshake]
handshakeList "" = Just []
handshakeList src = do
	(h, rest) <- handshakeOne src
	hs <- handshakeList rest
	return (h : hs)

handshakeOne :: BS.ByteString -> Maybe (Handshake, BS.ByteString)
handshakeOne src = do
	(ht, rest) <- BS.uncons src
	(bslen, rest') <- maybeSplitAt 3 rest
	len <- toLen bslen
	(body, rest'') <- maybeSplitAt len rest'
	return $ (handshake (handshakeType ht) body, rest'')

handshakeToByteString :: Handshake -> BS.ByteString
handshakeToByteString (HandshakeClientHello body) = handshakeToByteString $
	HandshakeRaw HandshakeTypeClientHello body
handshakeToByteString (HandshakeServerHello body) = handshakeToByteString $
	HandshakeRaw HandshakeTypeServerHello body
handshakeToByteString (HandshakeCertificate body) = handshakeToByteString $
	HandshakeRaw HandshakeTypeCertificate body
handshakeToByteString (HandshakeServerHelloDone body) = handshakeToByteString $
	HandshakeRaw HandshakeTypeServerHelloDone body
handshakeToByteString (HandshakeRaw ht body) =
	handshakeTypeToByteString ht `BS.append`
	fromLen 3 (BS.length body) `BS.append`
	body

data Handshake
	= HandshakeClientHello BS.ByteString
	| HandshakeServerHello BS.ByteString
	| HandshakeCertificate BS.ByteString
	| HandshakeServerHelloDone BS.ByteString
	| HandshakeRaw HandshakeType BS.ByteString
	deriving Show

handshake :: HandshakeType -> BS.ByteString -> Handshake
handshake HandshakeTypeClientHello body = HandshakeClientHello body
handshake HandshakeTypeServerHello body = HandshakeServerHello body
handshake HandshakeTypeCertificate body = HandshakeCertificate body
handshake HandshakeTypeServerHelloDone body = HandshakeServerHelloDone body
handshake ht body = HandshakeRaw ht body

handshakeToHandshakeType :: Handshake -> HandshakeType
handshakeToHandshakeType (HandshakeClientHello _) = HandshakeTypeClientHello
handshakeToHandshakeType (HandshakeServerHello _) = HandshakeTypeServerHello
handshakeToHandshakeType (HandshakeCertificate _) = HandshakeTypeCertificate
handshakeToHandshakeType (HandshakeServerHelloDone _) = HandshakeTypeServerHelloDone
handshakeToHandshakeType (HandshakeRaw ht _) = ht

data HandshakeType
	= HandshakeTypeClientHello
	| HandshakeTypeServerHello
	| HandshakeTypeCertificate
	| HandshakeTypeServerKeyExchange
	| HandshakeTypeServerHelloDone
	| HandshakeTypeFinished
	| HandshakeTypeRaw Word8
	deriving (Show, Eq)

handshakeType :: Word8 -> HandshakeType
handshakeType 1 = HandshakeTypeClientHello
handshakeType 2 = HandshakeTypeServerHello
handshakeType 11 = HandshakeTypeCertificate
handshakeType 12 = HandshakeTypeServerKeyExchange
handshakeType 14 = HandshakeTypeServerHelloDone
handshakeType 20 = HandshakeTypeFinished
handshakeType w = HandshakeTypeRaw w

handshakeTypeToByteString :: HandshakeType -> BS.ByteString
handshakeTypeToByteString HandshakeTypeClientHello = "\x01"
handshakeTypeToByteString HandshakeTypeServerHello = "\x02"
handshakeTypeToByteString HandshakeTypeCertificate = "\x0b"
handshakeTypeToByteString HandshakeTypeServerKeyExchange = "\x0c"
handshakeTypeToByteString HandshakeTypeServerHelloDone = "\x0e"
handshakeTypeToByteString HandshakeTypeFinished = "\x14"
handshakeTypeToByteString (HandshakeTypeRaw w) = BS.pack [w]
