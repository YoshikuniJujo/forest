{-# LANGUAGE OverloadedStrings #-}

module Content (
	Content,
	readContent
) where

import Prelude hiding (head, take)
import Control.Applicative

import Data.Conduit
import Data.Conduit.Network
import Data.Conduit.Binary
import Data.Word

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

import Version
import Handshake

readContent :: AppData -> IO (Maybe Content)
readContent ad = appSource ad $$ parseOne $= await

parseOne :: Monad m => Conduit BS.ByteString m Content
parseOne = do
	mt <- head
	v <- version
	mlen1 <- head
	mlen2 <- head
	case (mt, mlen1, mlen2) of
		(Just t, Just len1, Just len2) -> do
			body <- take $ fromIntegral len1 * 256 + fromIntegral len2
			case content (contentType t) v (LBS.toStrict body) of
				Just c -> yield c
				_ -> return ()
		_ -> return ()

data Content
	= ContentHandshake Version Handshake
	| Content ContentType Version BS.ByteString
	deriving Show

content :: ContentType -> Version -> BS.ByteString -> Maybe Content
content ContentTypeHandshake ver body =
	ContentHandshake ver <$> readHandshake body
content ct ver body = Just $ Content ct ver body

data ContentType
	= ContentTypeHandshake
	| ContentTypeOthers Word8
	deriving Show

contentType :: Word8 -> ContentType
contentType 22 = ContentTypeHandshake
contentType t = ContentTypeOthers t
