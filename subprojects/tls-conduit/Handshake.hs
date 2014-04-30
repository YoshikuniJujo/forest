{-# LANGUAGE OverloadedStrings #-}

module Handshake (Handshake, parseHandshake, parseHandshakeAll) where

import Control.Monad

import Data.Bits
import Data.Word
import qualified Data.ByteString as BS

parseHandshakeAll :: BS.ByteString -> Maybe [Handshake]
parseHandshakeAll "" = Just []
parseHandshakeAll src = do
	(h, rest) <- parseHandshake src
	hs <- parseHandshakeAll rest
	return (h : hs)

parseHandshake :: BS.ByteString -> Maybe (Handshake, BS.ByteString)
parseHandshake src = do
	(ht, rest) <- BS.uncons src
	(bslen, rest') <- maybeSplitAt 3 rest
	len <- toInt bslen
--	guard $ len == BS.length body
	(body, rest'') <- maybeSplitAt len rest'
	return $ (handshake (handshakeType ht) body, rest'')

data Handshake
	= HandshakeClientHello BS.ByteString
	| HandshakeServerHello BS.ByteString
	| HandshakeCertificate BS.ByteString
	| HandshakeServerHelloDone BS.ByteString
	| HandshakeOthers HandshakeType BS.ByteString
	deriving Show

handshake :: HandshakeType -> BS.ByteString -> Handshake
handshake HandshakeTypeClientHello body = HandshakeClientHello body
handshake HandshakeTypeServerHello body = HandshakeServerHello body
handshake HandshakeTypeCertificate body = HandshakeCertificate body
handshake HandshakeTypeServerHelloDone body = HandshakeServerHelloDone body
handshake ht body = HandshakeOthers ht body

data HandshakeType
	= HandshakeTypeClientHello
	| HandshakeTypeServerHello
	| HandshakeTypeCertificate
	| HandshakeTypeServerHelloDone
	| HandshakeTypeOthers Word8
	deriving Show

handshakeType :: Word8 -> HandshakeType
handshakeType 1 = HandshakeTypeClientHello
handshakeType 2 = HandshakeTypeServerHello
handshakeType 11 = HandshakeTypeCertificate
handshakeType 14 = HandshakeTypeServerHelloDone
handshakeType w = HandshakeTypeOthers w

maybeSplitAt :: Int -> BS.ByteString -> Maybe (BS.ByteString, BS.ByteString)
maybeSplitAt n bs = do
	guard $ n <= BS.length bs
	return $ BS.splitAt n bs

toInt :: BS.ByteString -> Maybe Int
toInt bs = do
	guard $ l <= 4
	return $ ti (l - 1) $ map fromIntegral $ BS.unpack bs
	where
	l = BS.length bs
	ti n _ | n < 0 = 0
	ti n (w : ws) = w `shift` (n * 8) .|. ti (n - 1) ws
