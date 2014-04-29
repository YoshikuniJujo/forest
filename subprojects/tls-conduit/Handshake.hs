{-# LANGUAGE OverloadedStrings, PackageImports, RankNTypes #-}

module Handshake (Handshake, readHandshake) where

import Prelude hiding (head, take)
-- import Control.Applicative
import Data.Word

import Data.Conduit
import qualified Data.Conduit.List as List
import Data.Conduit.Binary
import Data.ByteString.Lazy (toStrict)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

import "monads-tf" Control.Monad.Identity

import ClientHello
import Tools

readHandshake :: BS.ByteString -> Maybe Handshake
readHandshake src = runIdentity $
	sourceLbs (LBS.fromStrict src) $$ parseHandshake =$ await

parseHandshake :: Monad m => Conduit BS.ByteString m Handshake
parseHandshake = do
	mt <- head
	len <- getLen 3
	case mt of
		Just t -> handshake (handshakeType t) =<< take len
		_ -> return ()

data Handshake
	= HandshakeClientHello ClientHello
	| HandshakeOthers HandshakeType BS.ByteString
	deriving Show

handshake :: Monad m => HandshakeType -> LBS.ByteString -> Producer m Handshake
handshake HandshakeTypeClientHello body =
	sourceLbs body $= clientHello $= List.map HandshakeClientHello
handshake typ body = yield $ HandshakeOthers typ $ toStrict body

data HandshakeType
	= HandshakeTypeClientHello
	| HandshakeTypeOthers Word8
	deriving Show

handshakeType :: Word8 -> HandshakeType
handshakeType 1 = HandshakeTypeClientHello
handshakeType t = HandshakeTypeOthers t
