module Content (
	Content(..),
	content,
	contentToHandshakeList,
	contentToByteString
) where

import Control.Applicative

import qualified Data.ByteString as BS

import Handshake
import Parts
import Tools

data Content
	= ContentHandshake Version [Handshake]
	| ContentRaw ContentType Version BS.ByteString
	deriving Show

content :: ContentType -> Version -> BS.ByteString -> Either String Content
content ContentTypeHandshake v body =
	ContentHandshake v <$> handshakeList body
content ct v body = return $ ContentRaw ct v body

contentToByteString :: Content -> BS.ByteString
contentToByteString (ContentHandshake v hss) = contentToByteString $
	ContentRaw ContentTypeHandshake v $
		BS.concat $ map handshakeToByteString hss
contentToByteString (ContentRaw ct v body) = contentTypeToByteString ct
	`BS.append` versionToByteString v
	`BS.append` fromLen 2 (BS.length body)
	`BS.append` body

contentToHandshakeList :: Content -> Maybe [Handshake]
contentToHandshakeList (ContentHandshake _ hss) = Just hss
contentToHandshakeList _ = Nothing
