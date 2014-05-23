{-# LANGUAGE OverloadedStrings #-}

module Content (
	Content(..), fragmentToContent, contentToFragment, contentListToFragment,
	Handshake(..), ClientHello(..), ServerHello(..), SessionId(..),
	certificate, certificateRequest, serverHelloDone,
	changeCipherSpec, finished, applicationData,
	showHandshake,

	EncryptedPreMasterSecret(..),

	Version(..), Random(..),
	doesChangeCipherSpec,
	doesServerHelloDone,

	clientVersion, clientRandom, encryptedPreMasterSecret,
	certificateChain, digitalSign,
	makeVerify,
	makeClientKeyExchange,
	makeClientHello,

	serverVersion, serverRandom, serverCipherSuite, getFinish,
	getCertificateRequest,
	CertificateRequest,

	CipherSuite(..), CompressionMethod(..),
) where

import Prelude hiding (concat, head)

import Control.Applicative
import Data.X509

-- import Fragment
-- import ByteStringMonad
import Handshake
-- import PreMasterSecret
-- import Parts
import Data.ByteString(ByteString, pack, concat)
import Data.Word
import Types

showHandshake :: Content -> String
showHandshake (ContentHandshake _ hs) = show hs
showHandshake _ = ""

makeClientHello :: Random -> Content
makeClientHello cr = ContentHandshake (Version 3 3) . HandshakeClientHello $
	ClientHello (Version 3 3) cr (SessionId "")
		[TLS_RSA_WITH_AES_128_CBC_SHA]
		[CompressionMethodNull]
		Nothing

certificateRequest :: [DistinguishedName] -> Content
certificateRequest = ContentHandshake (Version 3 3)
	. HandshakeCertificateRequest
	. CertificateRequest
		[ClientCertificateTypeRsaSign]
		[(HashAlgorithmSha256, SignatureAlgorithmRsa)]

serverHelloDone :: Content
serverHelloDone = ContentHandshake (Version 3 3) HandshakeServerHelloDone

certificate :: CertificateChain -> Content
certificate = ContentHandshake (Version 3 3) . HandshakeCertificate

changeCipherSpec :: Content
changeCipherSpec = ContentChangeCipherSpec (Version 3 3) ChangeCipherSpec

finished :: ByteString -> Content
finished fh = ContentHandshake (Version 3 3) $ HandshakeFinished fh

applicationData :: ByteString -> Content
applicationData = ContentApplicationData (Version 3 3)

fragmentToContent :: Fragment -> Either String [Content]
fragmentToContent (Fragment ct v body) = evalByteStringM (parseContent ct v) body

parseContent :: ContentType -> Version -> ByteStringM [Content]
parseContent ContentTypeChangeCipherSpec v =
	map (ContentChangeCipherSpec v) <$> parse
parseContent ContentTypeAlert v = do
	al <- headBS
	ad <- headBS
	return [ContentAlert v al ad]
parseContent ContentTypeHandshake v =
	map (ContentHandshake v) <$> parse
parseContent ContentTypeApplicationData v =
	(: []) . ContentApplicationData v <$> whole
parseContent ct v = (: []) . ContentRaw ct v <$> whole

contentListToFragment :: [Content] -> Fragment
contentListToFragment cs = let
	fs@(Fragment ct vsn _ : _) = map contentToFragment cs in
	Fragment ct vsn . concat $ map (\(Fragment _ _ b) -> b) fs

contentToFragment :: Content -> Fragment
contentToFragment (ContentChangeCipherSpec v ccs) =
	Fragment ContentTypeChangeCipherSpec v $ changeCipherSpecToByteString ccs
contentToFragment (ContentAlert v al ad) =
	Fragment ContentTypeAlert v $ pack [al, ad]
contentToFragment (ContentHandshake v hss) = Fragment ContentTypeHandshake v $
	toByteString hss
contentToFragment (ContentApplicationData v body) =
	Fragment ContentTypeApplicationData v body
contentToFragment (ContentRaw ct v body) = Fragment ct v body

data Content
	= ContentChangeCipherSpec Version ChangeCipherSpec
	| ContentAlert Version Word8 Word8
	| ContentHandshake Version Handshake
	| ContentApplicationData Version ByteString
	| ContentRaw ContentType Version ByteString
	deriving Show

doesChangeCipherSpec :: Content -> Bool
doesChangeCipherSpec (ContentChangeCipherSpec _ ChangeCipherSpec) = True
doesChangeCipherSpec _ = False

doesServerHelloDone :: Content -> Bool
doesServerHelloDone (ContentHandshake _ HandshakeServerHelloDone) = True
doesServerHelloDone _ = False

data ChangeCipherSpec
	= ChangeCipherSpec
	| ChangeCipherSpecRaw Word8
	deriving Show

instance Parsable ChangeCipherSpec where
	parse = parseChangeCipherSpec
	toByteString = changeCipherSpecToByteString
	listLength _ = Nothing

parseChangeCipherSpec :: ByteStringM ChangeCipherSpec
parseChangeCipherSpec = do
	ccs <- headBS
	return $ case ccs of
		1 -> ChangeCipherSpec
		_ -> ChangeCipherSpecRaw ccs

changeCipherSpecToByteString :: ChangeCipherSpec -> ByteString
changeCipherSpecToByteString ChangeCipherSpec = pack [1]
changeCipherSpecToByteString (ChangeCipherSpecRaw ccs) = pack [ccs]

digitalSign :: Content -> Maybe ByteString
digitalSign (ContentHandshake _ hss) = handshakeSign hss
digitalSign _ = Nothing

makeVerify :: ByteString -> Content
makeVerify = ContentHandshake (Version 3 3) . handshakeMakeVerify

certificateChain :: Content -> Maybe CertificateChain
certificateChain (ContentHandshake _ hss) = handshakeCertificate hss
certificateChain _ = Nothing

clientRandom :: Content -> Maybe Random
clientRandom (ContentHandshake _ hss) = handshakeClientRandom hss
clientRandom _ = Nothing

clientVersion :: Content -> Maybe Version
clientVersion (ContentHandshake _ hss) = handshakeClientVersion hss
clientVersion _ = Nothing

encryptedPreMasterSecret :: Content -> Maybe EncryptedPreMasterSecret
encryptedPreMasterSecret (ContentHandshake _ hss) =
	handshakeEncryptedPreMasterSecret hss
encryptedPreMasterSecret _ = Nothing

makeClientKeyExchange :: EncryptedPreMasterSecret -> Content
makeClientKeyExchange =
	ContentHandshake (Version 3 3) . handshakeMakeClientKeyExchange

serverVersion :: Content -> Maybe Version
serverVersion (ContentHandshake _ hs) = handshakeServerVersion hs
serverVersion _ = Nothing

serverRandom :: Content -> Maybe Random
serverRandom (ContentHandshake _ hs) = handshakeServerRandom hs
serverRandom _ = Nothing

serverCipherSuite :: Content -> Maybe CipherSuite
serverCipherSuite (ContentHandshake _ hs) = handshakeCipherSuite hs
serverCipherSuite _ = Nothing

getFinish :: Content -> Maybe ByteString
getFinish (ContentHandshake _ hs) = handshakeGetFinish hs
getFinish _ = Nothing

getCertificateRequest :: Content -> Maybe CertificateRequest
getCertificateRequest (ContentHandshake _ hs) = handshakeCertificateRequest hs
getCertificateRequest _ = Nothing
