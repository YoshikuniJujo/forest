module Content (
	Content(..),
	fragmentToContent,
	contentToFragment
) where

import Prelude hiding (concat)

import Control.Applicative

import Fragment
import Handshake
import ByteStringMonad

fragmentToContent :: Fragment -> Either String Content
fragmentToContent (Fragment ct v body) = evalByteStringM (parseContent ct v) body

parseContent :: ContentType -> Version -> ByteStringM Content
parseContent ContentTypeHandshake v = ContentHandshake v <$> list1 parseHandshake
parseContent ct v = ContentRaw ct v <$> whole

contentToFragment :: Content -> Fragment
contentToFragment (ContentHandshake v hss) = Fragment ContentTypeHandshake v $
		concat $ map handshakeToByteString hss
contentToFragment (ContentRaw ct v body) = Fragment ct v body

data Content
	= ContentHandshake Version [Handshake]
	| ContentRaw ContentType Version ByteString
	deriving Show
