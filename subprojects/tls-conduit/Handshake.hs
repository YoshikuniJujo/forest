module Handshake (
	Handshake,
	byteStringToHandshakeList,
	handshakeListToByteString
) where

import Prelude hiding (head, take)

import Control.Applicative ((<$>), (<*>))

import Data.Word
import Data.ByteString (ByteString, append, pack)
import qualified Data.ByteString as BS

import ClientHello
import ByteStringMonad
import ToByteString

byteStringToHandshakeList :: ByteString -> Either String [Handshake]
byteStringToHandshakeList = evalByteStringM parseHandshakeList

parseHandshakeList :: ByteStringM [Handshake]
parseHandshakeList = do
	hs <- parseHandshake
	e <- empty
	if e then return [hs] else (hs :) <$> parseHandshakeList

parseHandshake :: ByteStringM Handshake
parseHandshake = do
	eh <- handshake <$> (byteStringToHandshakeType <$> head) <*> takeLen 3
	case eh of
		Right h -> return h
		Left err -> throwError err

handshakeListToByteString :: [Handshake] -> ByteString
handshakeListToByteString = BS.concat . map handshakeToByteString

handshakeToByteString :: Handshake -> ByteString
handshakeToByteString (HandshakeClientHello ch) = handshakeToByteString $
	HandshakeRaw HandshakeTypeClientHello $ clientHelloToByteString ch
handshakeToByteString (HandshakeRaw mt bs) =
	handshakeTypeToByteString mt `append` lenBodyToByteString 3 bs

data Handshake
	= HandshakeClientHello ClientHello
	| HandshakeRaw HandshakeType ByteString
	deriving Show

handshake :: HandshakeType -> ByteString -> Either String Handshake
handshake HandshakeTypeClientHello body = HandshakeClientHello <$>
	byteStringToClientHello body
handshake mt body = Right $ HandshakeRaw mt body

data HandshakeType
	= HandshakeTypeClientHello
	| HandshakeTypeRaw Word8
	deriving Show

byteStringToHandshakeType :: Word8 -> HandshakeType
byteStringToHandshakeType 1 = HandshakeTypeClientHello
byteStringToHandshakeType ht = HandshakeTypeRaw ht

handshakeTypeToByteString :: HandshakeType -> ByteString
handshakeTypeToByteString HandshakeTypeClientHello = pack [1]
handshakeTypeToByteString (HandshakeTypeRaw w) = pack [w]
