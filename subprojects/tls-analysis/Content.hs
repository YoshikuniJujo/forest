{-# LANGUAGE OverloadedStrings #-}

module Content (
	Content(ContentHandshake),
	EncryptedPreMasterSecret(..),

	fragmentToContent, contentToFragment,

	serverHello, certificate, certificateRequest, serverHelloDone,
	changeCipherSpec, finished,
	applicationData,

	doesChangeCipherSpec,

	version, cipherSuite,

	clientVersion, clientRandom, encryptedPreMasterSecret,
	certificateChain, digitalSign,

	toByteString,
) where

import Prelude hiding (concat, head)

import Control.Applicative
import Data.Maybe
import Data.X509

-- import Fragment
-- import ByteStringMonad
import Handshake
-- import PreMasterSecret
-- import Parts
import Data.ByteString(ByteString, pack, concat)
import Data.Word
import Basic

version :: Version
version = Version 3 3

serverHello :: Random -> Content
serverHello sr = ContentHandshake (Version 3 3) . (: []) . HandshakeServerHello $
	ServerHello (Version 3 3) sr (SessionId "")
		TLS_RSA_WITH_AES_128_CBC_SHA
		CompressionMethodNull
		Nothing

certificateRequest :: [DistinguishedName] -> Content
certificateRequest = ContentHandshake (Version 3 3) . (: [])
	. HandshakeCertificateRequest
	. CertificateRequest
		[ClientCertificateTypeRsaSign]
		[(HashAlgorithmSha256, SignatureAlgorithmRsa)]

serverHelloDone :: Content
serverHelloDone = ContentHandshake (Version 3 3) [HandshakeServerHelloDone]

certificate :: CertificateChain -> Content
certificate = ContentHandshake (Version 3 3) . (: []) . HandshakeCertificate

changeCipherSpec :: Content
changeCipherSpec = ContentChangeCipherSpec (Version 3 3) ChangeCipherSpec

finished :: ByteString -> Content
finished fh = ContentHandshake (Version 3 3) [HandshakeFinished fh]

applicationData :: ByteString -> Content
applicationData = ContentApplicationData (Version 3 3)

fragmentToContent :: Fragment -> Either String Content
fragmentToContent (Fragment ct v body) = evalByteStringM (parseContent ct v) body

parseContent :: ContentType -> Version -> ByteStringM Content
parseContent ContentTypeChangeCipherSpec v = ContentChangeCipherSpec v <$> parseChangeCipherSpec
parseContent ContentTypeHandshake v = ContentHandshake v <$> parse
parseContent ContentTypeApplicationData v = ContentApplicationData v <$> whole
parseContent ct v = ContentRaw ct v <$> whole

contentToFragment :: Content -> Fragment
contentToFragment (ContentChangeCipherSpec v ccs) =
	Fragment ContentTypeChangeCipherSpec v $ changeCipherSpecToByteString ccs
contentToFragment (ContentHandshake v hss) = Fragment ContentTypeHandshake v .
	concat $ map toByteString hss
contentToFragment (ContentApplicationData v body) =
	Fragment ContentTypeApplicationData v body
contentToFragment (ContentRaw ct v body) = Fragment ct v body

data Content
	= ContentChangeCipherSpec Version ChangeCipherSpec
	| ContentHandshake Version [Handshake]
	| ContentApplicationData Version ByteString
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
	ccs <- headBS
	return $ case ccs of
		1 -> ChangeCipherSpec
		_ -> ChangeCipherSpecRaw ccs

changeCipherSpecToByteString :: ChangeCipherSpec -> ByteString
changeCipherSpecToByteString ChangeCipherSpec = pack [1]
changeCipherSpecToByteString (ChangeCipherSpecRaw ccs) = pack [ccs]

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

clientRandom :: Content -> Maybe Random
clientRandom (ContentHandshake _ hss) = case mapMaybe handshakeClientRandom hss of
	[r] -> Just r
	_ -> Nothing
clientRandom _ = Nothing

clientVersion :: Content -> Maybe Version
clientVersion (ContentHandshake _ hss) = case mapMaybe handshakeClientVersion hss of
	[v] -> Just v
	_ -> Nothing
clientVersion _ = Nothing

cipherSuite :: CipherSuite
cipherSuite = TLS_RSA_WITH_AES_128_CBC_SHA

encryptedPreMasterSecret :: Content -> Maybe EncryptedPreMasterSecret
encryptedPreMasterSecret (ContentHandshake _ hss) =
	case mapMaybe handshakeEncryptedPreMasterSecret hss of
		[epms] -> Just epms
		_ -> Nothing
encryptedPreMasterSecret _ = Nothing
