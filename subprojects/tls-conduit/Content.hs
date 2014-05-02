module Content (
	fragmentToContent,
	contentToFragment
) where

import Control.Applicative

import Data.ByteString (ByteString)

import Fragment
import Handshake

fragmentToContent :: Fragment -> Either String Content
fragmentToContent (Fragment ContentTypeHandshake v body) = ContentHandshake v <$>
	byteStringToHandshakeList body
fragmentToContent (Fragment ct v body) = return $ ContentRaw ct v body

contentToFragment :: Content -> Fragment
contentToFragment (ContentHandshake v hss) =
	Fragment ContentTypeHandshake v $
		handshakeListToByteString hss
contentToFragment (ContentRaw ct v body) = Fragment ct v body

data Content
	= ContentHandshake Version [Handshake]
	| ContentRaw ContentType Version ByteString
	deriving Show
