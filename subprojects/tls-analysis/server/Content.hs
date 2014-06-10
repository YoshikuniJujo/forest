{-# LANGUAGE OverloadedStrings #-}

module Content (
	Content(..), getContent, contentToFragment, contentListToFragment,
	ChangeCipherSpec(..),

	Handshake(..),
	ClientHello(..), ServerHello(..),
	Version(..), Random(..), SessionId(..),
	CipherSuite(..), CipherSuiteKeyEx(..), CipherSuiteMsgEnc(..),
	CompressionMethod(..),
	EncryptedPreMasterSecret(..),
	CertificateRequest(..),
	ClientCertificateType(..), HashAlgorithm(..), SignatureAlgorithm(..),
	DigitallySigned(..),

	contentToByteString,
	contentListToByteString,

	ContentType(..),
) where

import Control.Monad
import Data.Word
import qualified Data.ByteString as BS
import Handshake
import Types

getContent :: Monad m =>
	m ContentType -> (Int -> m (ContentType, BS.ByteString)) -> m Content
getContent rct rd = do
	ct <- rct
	parseContent ((snd `liftM`) . rd) ct (Version 3 3)

parseContent :: Monad m =>
	(Int -> m BS.ByteString) -> ContentType -> Version -> m Content
parseContent rd ContentTypeChangeCipherSpec v =
	ContentChangeCipherSpec v `liftM` parse' rd
parseContent rd ContentTypeAlert v = do
	[al, ad] <- BS.unpack `liftM` rd 2
	return $ ContentAlert v al ad
parseContent rd ContentTypeHandshake v = ContentHandshake v `liftM` parse' rd
parseContent _ ContentTypeApplicationData _ = undefined
parseContent _ _ _ = undefined

contentListToFragment :: [Content] -> Fragment
contentListToFragment cs = let
	fs@(Fragment ct vsn _ : _) = map contentToFragment cs in
	Fragment ct vsn . BS.concat $ map (\(Fragment _ _ b) -> b) fs

contentListToByteString :: [Content] -> (ContentType, BS.ByteString)
contentListToByteString cs = let Fragment ct _ bs = contentListToFragment cs in
	(ct, bs)

contentToFragment :: Content -> Fragment
contentToFragment (ContentChangeCipherSpec v ccs) =
	Fragment ContentTypeChangeCipherSpec v $ changeCipherSpecToByteString ccs
contentToFragment (ContentAlert v al ad) =
	Fragment ContentTypeAlert v $ BS.pack [al, ad]
contentToFragment (ContentHandshake v hss) = Fragment ContentTypeHandshake v $
	toByteString' hss
contentToFragment (ContentApplicationData v body) =
	Fragment ContentTypeApplicationData v body
contentToFragment (ContentRaw ct v body) = Fragment ct v body

contentToByteString :: Content -> (ContentType, BS.ByteString)
contentToByteString c = let Fragment ct _ bs = contentToFragment c in (ct, bs)

data Content
	= ContentChangeCipherSpec Version ChangeCipherSpec
	| ContentAlert Version Word8 Word8
	| ContentHandshake Version Handshake
	| ContentApplicationData Version BS.ByteString
	| ContentRaw ContentType Version BS.ByteString
	deriving Show

data ChangeCipherSpec
	= ChangeCipherSpec
	| ChangeCipherSpecRaw Word8
	deriving Show

instance Parsable' ChangeCipherSpec where
	parse' = parseChangeCipherSpec'
	toByteString' = changeCipherSpecToByteString

parseChangeCipherSpec' :: Monad m => (Int -> m BS.ByteString) -> m ChangeCipherSpec
parseChangeCipherSpec' rd = do
	[ccs] <- BS.unpack `liftM` rd 1
	return $ case ccs of
		1 -> ChangeCipherSpec
		_ -> ChangeCipherSpecRaw ccs

changeCipherSpecToByteString :: ChangeCipherSpec -> BS.ByteString
changeCipherSpecToByteString ChangeCipherSpec = BS.pack [1]
changeCipherSpecToByteString (ChangeCipherSpecRaw ccs) = BS.pack [ccs]

data Fragment
	= Fragment ContentType Version BS.ByteString
	deriving Show
