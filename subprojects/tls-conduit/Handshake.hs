{-# LANGUAGE OverloadedStrings, PackageImports #-}

module Handshake (
	Handshake,
	readHandshake
) where

import Prelude hiding (head, take)
import Control.Applicative
import Data.Word

import Data.Conduit
import Data.Conduit.Binary
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

import "monads-tf" Control.Monad.Identity

import ClientHello

readHandshake :: BS.ByteString -> Maybe Handshake
readHandshake src = runIdentity $
	sourceLbs (LBS.fromStrict src) $$ parseHandshake =$ await

parseHandshake :: Monad m => Conduit BS.ByteString m Handshake
parseHandshake = do
	mt <- head
	len <- toLen <$> take 3
	case mt of
		Just t -> do
			body <- take len
			case handshake (handshakeType t) $ LBS.toStrict body of
				Just hs -> yield hs
				_ -> return ()
		_ -> return ()

toLen :: LBS.ByteString -> Int
toLen bs = let
	ws = map fromIntegral $ LBS.unpack bs in
	mkOne (LBS.length bs - 1) ws
	where
	mkOne _ [] = 0
	mkOne n (x : xs) = x * 256 ^ n + mkOne (n - 1) xs

data Handshake
	= HandshakeClientHello ClientHello
	| HandshakeOthers HandshakeType BS.ByteString
	deriving Show

handshake :: HandshakeType -> BS.ByteString -> Maybe Handshake
handshake HandshakeTypeClientHello src =
	HandshakeClientHello <$> readClientHello src
handshake typ src = Just $ HandshakeOthers typ src

data HandshakeType
	= HandshakeTypeClientHello
	| HandshakeTypeOthers Word8
	deriving Show

handshakeType :: Word8 -> HandshakeType
handshakeType 1 = HandshakeTypeClientHello
handshakeType t = HandshakeTypeOthers t
