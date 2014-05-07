{-# LANGUAGE OverloadedStrings #-}

module CertificateRequest (
	CertificateRequest,
	parseCertificateRequest, certificateRequestToByteString,
) where

import Prelude hiding (head)

import Control.Applicative
import qualified Data.ByteString as BS
import ByteStringMonad
import ToByteString
import Parts

data CertificateRequest
	= CertificateRequest [ClientCertificateType]
		[(HashAlgorithm, SignatureAlgorithm)] [ByteString]
	| CertificateRequestRaw ByteString
	deriving Show

parseCertificateRequest :: ByteStringM CertificateRequest
parseCertificateRequest = do
	ccts <- section 1 $ list1 parseClientCertificateType
	hasas <- section 2 $ list1 parseHashSignatureAlgorithm
	dns <- section 2 . list $ takeLen 2
	return $ CertificateRequest ccts hasas dns

certificateRequestToByteString :: CertificateRequest -> ByteString
certificateRequestToByteString (CertificateRequest ccts hsas bss) = BS.concat [
	lenBodyToByteString 1 . BS.concat $
		map clientCertificateTypeToByteString ccts,
	lenBodyToByteString 2 . BS.concat $
		map hashSignatureAlgorithmToByteString hsas,
	lenBodyToByteString 2 . BS.concat $
		map (lenBodyToByteString 2) bss ]
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
