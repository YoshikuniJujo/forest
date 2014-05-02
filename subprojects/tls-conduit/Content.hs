module Content (
	Content(..), fragmentToContent, contentToFragment,
	doesServerHelloFinish, doesFinish,
	doesClientKeyExchange,
	clientRandom, serverRandom, encryptedPreMasterSecret,
) where

import Prelude hiding (concat)

import Control.Applicative
import Data.Maybe

import Fragment
import ByteStringMonad
import Handshake
import PreMasterSecret
import Parts

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

doesServerHelloFinish :: Content -> Bool
doesServerHelloFinish (ContentHandshake _ hss) =
	any handshakeDoesServerHelloFinish hss
doesServerHelloFinish _ = False

doesFinish :: Content -> Bool
doesFinish (ContentHandshake _ hss) = any handshakeDoesFinish hss
doesFinish _ = False

doesClientKeyExchange :: Content -> Bool
doesClientKeyExchange (ContentHandshake _ hss) =
	any handshakeDoesClientKeyExchange hss
doesClientKeyExchange _ = False

clientRandom, serverRandom :: Content -> Maybe Random
clientRandom (ContentHandshake _ hss) = case mapMaybe handshakeClientRandom hss of
	[r] -> Just r
	_ -> Nothing
clientRandom _ = Nothing
serverRandom (ContentHandshake _ hss) = case mapMaybe handshakeServerRandom hss of
	[r] -> Just r
	_ -> Nothing
serverRandom _ = Nothing

encryptedPreMasterSecret :: Content -> Maybe EncryptedPreMasterSecret
encryptedPreMasterSecret (ContentHandshake _ hss) =
	case mapMaybe handshakeEncryptedPreMasterSecret hss of
		[epms] -> Just epms
		_ -> Nothing
encryptedPreMasterSecret _ = Nothing
