module Content (
	Content(..), fragmentToContent, contentToFragment,
	ChangeCipherSpec(..), doesChangeCipherSpec,
	doesServerHelloFinish, doesFinish,
	doesClientKeyExchange,
	clientRandom, serverRandom, cipherSuite,
	clientVersion, serverVersion,
	encryptedPreMasterSecret,
	onlyKnownCipherSuite,
	certificateChain,
	digitalSign,
) where

import Prelude hiding (concat, head)

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
parseContent ContentTypeChangeCipherSpec v = ContentChangeCipherSpec v <$> parseChangeCipherSpec
parseContent ContentTypeHandshake v = ContentHandshake v <$> list1 parseHandshake
parseContent ct v = ContentRaw ct v <$> whole

contentToFragment :: Content -> Fragment
contentToFragment (ContentChangeCipherSpec v ccs) =
	Fragment ContentTypeChangeCipherSpec v $ changeCipherSpecToByteString ccs
contentToFragment (ContentHandshake v hss) = Fragment ContentTypeHandshake v .
		concat $ map handshakeToByteString hss
contentToFragment (ContentRaw ct v body) = Fragment ct v body

data Content
	= ContentChangeCipherSpec Version ChangeCipherSpec
	| ContentHandshake Version [Handshake]
	| ContentRaw ContentType Version ByteString
	deriving Show

doesChangeCipherSpec :: Content -> Bool
doesChangeCipherSpec (ContentChangeCipherSpec _ ChangeCipherSpec) = True
doesChangeCipherSpec _ = False

data ChangeCipherSpec
	= ChangeCipherSpec
	| ChangeCipherSpecRaw Word8
	deriving Show

parseChangeCipherSpec :: ByteStringM ChangeCipherSpec
parseChangeCipherSpec = do
	ccs <- head
	return $ case ccs of
		1 -> ChangeCipherSpec
		_ -> ChangeCipherSpecRaw ccs

changeCipherSpecToByteString :: ChangeCipherSpec -> ByteString
changeCipherSpecToByteString ChangeCipherSpec = pack [1]
changeCipherSpecToByteString (ChangeCipherSpecRaw ccs) = pack [ccs]

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

digitalSign :: Content -> Maybe ByteString
digitalSign (ContentHandshake _ hss) = case mapMaybe handshakeSign hss of
	[ds] -> Just ds
	_ -> Nothing
digitalSign _ = Nothing

certificateChain :: Content -> Maybe CertificateChain
certificateChain (ContentHandshake _ hss) = case mapMaybe handshakeCertificate hss of
	[cc] -> Just cc
	_ -> Nothing
certificateChain _ = Nothing

clientRandom, serverRandom :: Content -> Maybe Random
clientRandom (ContentHandshake _ hss) = case mapMaybe handshakeClientRandom hss of
	[r] -> Just r
	_ -> Nothing
clientRandom _ = Nothing
serverRandom (ContentHandshake _ hss) = case mapMaybe handshakeServerRandom hss of
	[r] -> Just r
	_ -> Nothing
serverRandom _ = Nothing

clientVersion :: Content -> Maybe ProtocolVersion
clientVersion (ContentHandshake _ hss) = case mapMaybe handshakeClientVersion hss of
	[v] -> Just v
	_ -> Nothing
clientVersion _ = Nothing

serverVersion :: Content -> Maybe ProtocolVersion
serverVersion (ContentHandshake _ hss) = case mapMaybe handshakeServerVersion hss of
	[v] -> Just v
	_ -> Nothing
serverVersion _ = Nothing

cipherSuite :: Content -> Maybe CipherSuite
cipherSuite (ContentHandshake _ hss) = case mapMaybe handshakeCipherSuite hss of
	[cs] -> Just cs
	_ -> Nothing
cipherSuite _ = Nothing

encryptedPreMasterSecret :: Content -> Maybe EncryptedPreMasterSecret
encryptedPreMasterSecret (ContentHandshake _ hss) =
	case mapMaybe handshakeEncryptedPreMasterSecret hss of
		[epms] -> Just epms
		_ -> Nothing
encryptedPreMasterSecret _ = Nothing

onlyKnownCipherSuite :: Content -> Content
onlyKnownCipherSuite (ContentHandshake v hss) =
	ContentHandshake v $ map handshakeOnlyKnownCipherSuite hss
onlyKnownCipherSuite c = c
