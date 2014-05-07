{-# LANGUAGE OverloadedStrings #-}

module CertificateRequest (
	CertificateRequest,
	parseCertificateRequest, certificateRequestToByteString,
) where

import Prelude hiding (head)

import Control.Applicative
import qualified Data.ByteString as BS

import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.Types
import Data.X509

import ByteStringMonad
import ToByteString
import Parts

data CertificateRequest
	= CertificateRequest [ClientCertificateType]
		[(HashAlgorithm, SignatureAlgorithm)] [DistinguishedName]
	| CertificateRequestRaw ByteString
	deriving Show

parseCertificateRequest :: ByteStringM CertificateRequest
parseCertificateRequest = do
	ccts <- section 1 $ list1 parseClientCertificateType
	hasas <- section 2 $ list1 parseHashSignatureAlgorithm
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
	lenBodyToByteString 2 . BS.concat $
		map hashSignatureAlgorithmToByteString hsas,
	lenBodyToByteString 2 . BS.concat $
		map (lenBodyToByteString 2) $ map (encodeASN1' DER . flip toASN1 []) bss ]
certificateRequestToByteString (CertificateRequestRaw bs) = bs

data ClientCertificateType
	= ClientCertificateTypeRsaSign
	| ClientCertificateTypeRaw Word8
	deriving Show

parseClientCertificateType :: ByteStringM ClientCertificateType
parseClientCertificateType = do
	cct <- head
	return $ case cct of
		1 -> ClientCertificateTypeRsaSign
		_ -> ClientCertificateTypeRaw cct

clientCertificateTypeToByteString :: ClientCertificateType -> ByteString
clientCertificateTypeToByteString ClientCertificateTypeRsaSign = "\x01"
clientCertificateTypeToByteString (ClientCertificateTypeRaw w) = BS.pack [w]

-- data SignatureAnd
