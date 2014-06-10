{-# LANGUAGE OverloadedStrings #-}

module Content (
	Content(..), getContent,
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
	parseContent ((snd `liftM`) . rd) ct

parseContent :: Monad m =>
	(Int -> m BS.ByteString) -> ContentType -> m Content
parseContent rd ContentTypeChangeCipherSpec =
	ContentChangeCipherSpec `liftM` parse' rd
parseContent rd ContentTypeAlert = do
	[al, ad] <- BS.unpack `liftM` rd 2
	return $ ContentAlert al ad
parseContent rd ContentTypeHandshake = ContentHandshake `liftM` parse' rd
parseContent _ ContentTypeApplicationData = undefined
parseContent _ _ = undefined

contentListToByteString :: [Content] -> (ContentType, BS.ByteString)
contentListToByteString cs = let fs@((ct, _) : _) = map contentToByteString cs in
	(ct, BS.concat $ map snd fs)

contentToByteString :: Content -> (ContentType, BS.ByteString)
contentToByteString (ContentChangeCipherSpec ccs) =
	(ContentTypeChangeCipherSpec, changeCipherSpecToByteString ccs)
contentToByteString (ContentAlert al ad) = (ContentTypeAlert, BS.pack [al, ad])
contentToByteString (ContentHandshake hss) =
	(ContentTypeHandshake, toByteString' hss)
contentToByteString (ContentApplicationData body) =
	(ContentTypeApplicationData, body)
contentToByteString (ContentRaw ct body) = (ct, body)

data Content
	= ContentChangeCipherSpec ChangeCipherSpec
	| ContentAlert Word8 Word8
	| ContentHandshake Handshake
	| ContentApplicationData BS.ByteString
	| ContentRaw ContentType BS.ByteString
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
