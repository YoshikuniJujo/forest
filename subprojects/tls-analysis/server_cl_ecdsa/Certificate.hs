{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Certificate (
	X509.CertificateChain,
	CertificateRequest(..),
	ClientCertificateType(..),
	EncryptedPreMasterSecret(..),
	DigitallySigned(..),

	section, whole, headBS,
) where

import Prelude hiding (concat)

import Control.Applicative
import qualified Data.X509 as X509
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.Types
import Numeric

import ByteStringMonad
import qualified Data.ByteString as BS
import Parts

-- import PreMasterSecret
-- import DigitallySigned

data Certificate
	= CertificateRaw ByteString
	deriving Show

instance Parsable X509.CertificateChain where
	parse = parseCertificateChain
	toByteString = certificateChainToByteString
	listLength _ = Nothing

parseCertificateChain :: ByteStringM X509.CertificateChain
parseCertificateChain = do
	ecc <- decodeCert <$> parseCertificateList
	case ecc of
		Right cc -> return cc
		Left (n, err) -> throwError $ show n ++ " " ++ err

certificateChainToByteString :: X509.CertificateChain -> ByteString
certificateChainToByteString = certificateListToByteString . encodeCert

decodeCert :: [Certificate] -> Either (Int, String) X509.CertificateChain
decodeCert = X509.decodeCertificateChain . X509.CertificateChainRaw .
	map (\(CertificateRaw c) -> c)

encodeCert :: X509.CertificateChain -> [Certificate]
encodeCert = (\(X509.CertificateChainRaw ccr) -> map CertificateRaw ccr) .
	X509.encodeCertificateChain

parseCertificateList :: ByteStringM [Certificate]
parseCertificateList = section 3 $ list parseCertificate

certificateListToByteString :: [Certificate] -> ByteString
certificateListToByteString =
	lenBodyToByteString 3 . BS.concat . map certificateToByteString

parseCertificate :: ByteStringM Certificate
parseCertificate = CertificateRaw <$> takeLen 3

certificateToByteString :: Certificate -> ByteString
certificateToByteString (CertificateRaw crt) = lenBodyToByteString 3 crt

data CertificateRequest
	= CertificateRequest [ClientCertificateType]
		[(HashAlgorithm, SignatureAlgorithm)] [X509.DistinguishedName]
	| CertificateRequestRaw ByteString
	deriving Show

instance Parsable CertificateRequest where
	parse = parseCertificateRequest
	toByteString = certificateRequestToByteString
	listLength _ = Nothing

parseCertificateRequest :: ByteStringM CertificateRequest
parseCertificateRequest = do
	ccts <- section 1 $ list1 parseClientCertificateType
	hasas <- parse -- section 2 $ list1 parseHashSignatureAlgorithm
	dns <- section 2 . list $ do
		bs <- takeLen 2
		asn1 <- case decodeASN1' DER bs of
			Right a -> return a
			Left err -> throwError $ show err
		case fromASN1 asn1 of
			Right (dn, _) -> return dn
			Left err -> throwError err
	return $ CertificateRequest ccts hasas dns

certificateRequestToByteString :: CertificateRequest -> ByteString
certificateRequestToByteString (CertificateRequest ccts hsas bss) = BS.concat [
	lenBodyToByteString 1 . BS.concat $
		map clientCertificateTypeToByteString ccts,
		toByteString hsas,
		{-
	lenBodyToByteString 2 . BS.concat $
		map hashSignatureAlgorithmToByteString hsas,
		-}
	lenBodyToByteString 2 . BS.concat $
		map (lenBodyToByteString 2 . encodeASN1' DER . flip toASN1 []) bss ]
certificateRequestToByteString (CertificateRequestRaw bs) = bs

data ClientCertificateType
	= ClientCertificateTypeRsaSign
	| ClientCertificateTypeEcdsaSign
	| ClientCertificateTypeRaw Word8
	deriving Show

parseClientCertificateType :: ByteStringM ClientCertificateType
parseClientCertificateType = do
	cct <- headBS
	return $ case cct of
		1 -> ClientCertificateTypeRsaSign
		64 -> ClientCertificateTypeEcdsaSign
		_ -> ClientCertificateTypeRaw cct

clientCertificateTypeToByteString :: ClientCertificateType -> ByteString
clientCertificateTypeToByteString ClientCertificateTypeRsaSign = "\x01"
clientCertificateTypeToByteString ClientCertificateTypeEcdsaSign = "\64"
clientCertificateTypeToByteString (ClientCertificateTypeRaw w) = BS.pack [w]

-- data SignatureAnd

data EncryptedPreMasterSecret
	= EncryptedPreMasterSecret { getEncryptedPreMasterSecret :: ByteString }

instance Show EncryptedPreMasterSecret where
	show (EncryptedPreMasterSecret epms) = "(EncryptedPreMasterSecret " ++
		showKeyPMS epms ++ ")"

instance Parsable EncryptedPreMasterSecret where
	parse = parseEncryptedPreMasterSecret
	toByteString = encryptedPreMasterSecretToByteString
	listLength _ = Nothing

showKeyPMS :: ByteString -> String
showKeyPMS = concatMap showH . unpack

showH :: Word8 -> String
showH w = replicate (2 - length s) '0' ++ s
	where
	s = showHex w ""

parseEncryptedPreMasterSecret :: ByteStringM EncryptedPreMasterSecret
parseEncryptedPreMasterSecret = EncryptedPreMasterSecret <$> takeLen 1

encryptedPreMasterSecretToByteString :: EncryptedPreMasterSecret -> ByteString
encryptedPreMasterSecretToByteString (EncryptedPreMasterSecret epms) =
	lenBodyToByteString 1 epms

data DigitallySigned
	= DigitallySigned (HashAlgorithm, SignatureAlgorithm) ByteString
	| DigitallySignedRaw ByteString
	deriving Show

instance Parsable DigitallySigned where
	parse = parseDigitallySigned
	toByteString = digitallySignedToByteString
	listLength _ = Nothing

parseDigitallySigned :: ByteStringM DigitallySigned
parseDigitallySigned = DigitallySigned
	<$> ((,) <$> parse <*> parseSignatureAlgorithm)
	<*> takeLen 2

digitallySignedToByteString :: DigitallySigned -> ByteString
digitallySignedToByteString (DigitallySigned (ha, sa) bs) = BS.concat [
	toByteString ha,
	toByteString sa,
	lenBodyToByteString 2 bs ]
digitallySignedToByteString (DigitallySignedRaw bs) = bs
