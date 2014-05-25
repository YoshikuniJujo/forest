{-# LANGUAGE OverloadedStrings #-}

module Content (
	Content, fragmentToContent, contentToFragment, contentListToFragment,
	serverHello, certificate, certificateRequest,
	changeCipherSpec, finished, applicationData,
	showHandshake,

	EncryptedPreMasterSecret(..),

	version,
	doesChangeCipherSpec,
	doesServerHelloDone,

	clientVersion, clientRandom, encryptedPreMasterSecret,
	certificateChain, digitalSign,
	makeVerify,
	makeClientKeyExchange,

	serverVersion, serverRandom, serverCipherSuite, getFinish,
	getCertificateRequest,
	clientHello,
	CertificateRequest(..),

	isFatal,
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
import qualified Data.ByteString as BS
import Data.Word
import Basic

showHandshake :: Content -> String
showHandshake (ContentHandshake _ hs) = show hs
showHandshake _ = ""

version :: Version
version = Version 3 3

serverHello :: Random -> Content
serverHello sr = ContentHandshake (Version 3 3) . HandshakeServerHello $
	ServerHello (Version 3 3) sr (SessionId "")
		TLS_RSA_WITH_AES_128_CBC_SHA
		CompressionMethodNull
		Nothing

clientHello :: Random -> (Word8, Word8) -> Content
clientHello cr (vmjr, vmnr) =
	ContentHandshake (Version vmjr vmnr) . HandshakeClientHello $
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
parseContent ContentTypeAlert v = (: []) . ContentAlert v <$> parse
parseContent ContentTypeHandshake v = map (ContentHandshake v) <$> parse
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
contentToFragment (ContentAlert v alt) =
	Fragment ContentTypeAlert v $ toByteString alt
contentToFragment (ContentHandshake v hss) = Fragment ContentTypeHandshake v $
	toByteString hss
contentToFragment (ContentApplicationData v body) =
	Fragment ContentTypeApplicationData v body
contentToFragment (ContentRaw ct v body) = Fragment ct v body

data Content
	= ContentChangeCipherSpec Version ChangeCipherSpec
	| ContentAlert Version Alert
	| ContentHandshake Version Handshake
	| ContentApplicationData Version ByteString
	| ContentRaw ContentType Version ByteString
	deriving Show

isFatal :: Content -> Bool
isFatal (ContentAlert _ (Alert AlertLevelFatal _)) = True
isFatal _ = False

data Alert = Alert AlertLevel AlertDescription deriving Show

data AlertLevel
	= AlertLevelWarning
	| AlertLevelFatal
	| AlertLevelRaw Word8
	deriving Show

data AlertDescription
	= AlertDescriptionCloseNotify
	| AlertDescriptionBadRecordMac
	| AlertDescriptionProtocolVersion
	| AlertDescriptionRaw Word8
	deriving Show

instance Parsable Alert where
	parse = parseAlert
	toByteString = alertToByteString
	listLength = const Nothing

parseAlert :: ByteStringM Alert
parseAlert = do
	al <- parseAlertLevel
	ad <- parseAlertDescription
	return $ Alert al ad

parseAlertLevel :: ByteStringM AlertLevel
parseAlertLevel = do
	al <- headBS
	return $ case al of
		1 -> AlertLevelWarning
		2 -> AlertLevelFatal
		_ -> AlertLevelRaw al

parseAlertDescription :: ByteStringM AlertDescription
parseAlertDescription = do
	ad <- headBS
	return $ case ad of
		0 -> AlertDescriptionCloseNotify
		20 -> AlertDescriptionBadRecordMac
		70 -> AlertDescriptionProtocolVersion
		_ -> AlertDescriptionRaw ad

alertToByteString :: Alert -> ByteString
alertToByteString (Alert al ad) =
	BS.pack [alertLevelToWord8 al, alertDescriptionToWord8 ad]

alertLevelToWord8 :: AlertLevel -> Word8
alertLevelToWord8 AlertLevelWarning = 1
alertLevelToWord8 AlertLevelFatal = 2
alertLevelToWord8 (AlertLevelRaw al) = al

alertDescriptionToWord8 :: AlertDescription -> Word8
alertDescriptionToWord8 AlertDescriptionCloseNotify = 0
alertDescriptionToWord8 AlertDescriptionBadRecordMac = 20
alertDescriptionToWord8 AlertDescriptionProtocolVersion = 70
alertDescriptionToWord8 (AlertDescriptionRaw ad) = ad

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
