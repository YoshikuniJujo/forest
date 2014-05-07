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

import ByteStringMonad
import ToByteString
import Parts

data CertificateRequest
	= CertificateRequest [ClientCertificateType]
		[(HashAlgorithm, SignatureAlgorithm)] [[ASN1]]
	| CertificateRequestRaw ByteString
	deriving Show

parseCertificateRequest :: ByteStringM CertificateRequest
parseCertificateRequest = do
	ccts <- section 1 $ list1 parseClientCertificateType
	hasas <- section 2 $ list1 parseHashSignatureAlgorithm
	dns <- section 2 . list $ do
		bs <- takeLen 2
		case decodeASN1' DER bs of
			Right asn1 -> return asn1
			Left err -> throwError $ show err
	return $ CertificateRequest ccts hasas dns

certificateRequestToByteString :: CertificateRequest -> ByteString
certificateRequestToByteString (CertificateRequest ccts hsas bss) = BS.concat [
	lenBodyToByteString 1 . BS.concat $
		map clientCertificateTypeToByteString ccts,
	lenBodyToByteString 2 . BS.concat $
		map hashSignatureAlgorithmToByteString hsas,
	lenBodyToByteString 2 . BS.concat $
		map (lenBodyToByteString 2) $ map (encodeASN1' DER) bss ]
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
