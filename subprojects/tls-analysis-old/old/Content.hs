{-# LANGUAGE OverloadedStrings #-}

module Content (
	Content,
	readContent,
	parseContent,
	fragment,
	contentToByteString
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
readContent ad = appSource ad $$ parseContent $= await

fragment :: AppData -> IO LBS.ByteString
fragment ad = appSource ad $$ takeFragment

takeFragment :: Monad m => Sink BS.ByteString m LBS.ByteString
takeFragment = do
	h <- take 3
	len <- take 2
	body <- take $ toLen len
	return $ h `LBS.append` len `LBS.append` body

toLen :: LBS.ByteString -> Int
toLen bs = let
	ws = map fromIntegral $ LBS.unpack bs in
	mkOne (LBS.length bs - 1) ws
	where
	mkOne _ [] = 0
	mkOne n (x : xs) = x * 256 ^ n + mkOne (n - 1) xs

parseContent :: Monad m => Conduit BS.ByteString m Content
parseContent = do
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
			parseContent
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
	| ContentTypeApplicationData
	| ContentTypeOthers Word8
	deriving Show

contentType :: Word8 -> ContentType
contentType 22 = ContentTypeHandshake
contentType 23 = ContentTypeApplicationData
contentType t = ContentTypeOthers t

contentToByteString :: Content -> BS.ByteString
contentToByteString (ContentHandshake v hs) =
	"\x16" `BS.append` versionToByteString v `BS.append`
		handshakeToByteString hs
contentToByteString _ = error "yet"
