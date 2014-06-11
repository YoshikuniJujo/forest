{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Certificate (
	X509.CertificateChain,
	CertificateRequest(..),
	ClientCertificateType(..),
	EncryptedPreMasterSecret(..),
	DigitallySigned(..),

	takeLen',
) where

import Prelude hiding (concat)

import Control.Applicative
import qualified Data.X509 as X509
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.Types
import Numeric
import Data.Word

import qualified Data.ByteString as BS
import Types

import qualified Codec.Bytable as B

data Certificate
	= CertificateRaw BS.ByteString
	deriving Show

instance B.Bytable X509.CertificateChain where
	fromByteString = B.evalBytableM B.parse
	toByteString = certificateChainToByteString

instance B.Parsable X509.CertificateChain where
	parse = parseCertificateChain'

parseCertificateChain' :: B.BytableM X509.CertificateChain
parseCertificateChain' = do
	ecc <- decodeCert <$> parseCertificateList'
	case ecc of
		Right cc -> return cc
		Left (n, err) -> fail $ show n ++ " " ++ err

parseCertificateList' :: B.BytableM [Certificate]
parseCertificateList' = do
	len <- B.take 3
	B.list len B.parse

instance B.Parsable Certificate where
	parse = parseCertificate'

parseCertificate' :: B.BytableM Certificate
parseCertificate' = B.take =<< B.take 3

instance B.Bytable Certificate where
	fromByteString = Right . CertificateRaw
	toByteString (CertificateRaw bs) = bs

certificateChainToByteString :: X509.CertificateChain -> BS.ByteString
certificateChainToByteString = certificateListToByteString . encodeCert

decodeCert :: [Certificate] -> Either (Int, String) X509.CertificateChain
decodeCert = X509.decodeCertificateChain . X509.CertificateChainRaw .
	map (\(CertificateRaw c) -> c)

encodeCert :: X509.CertificateChain -> [Certificate]
encodeCert = (\(X509.CertificateChainRaw ccr) -> map CertificateRaw ccr) .
	X509.encodeCertificateChain

certificateListToByteString :: [Certificate] -> BS.ByteString
certificateListToByteString =
	lenBodyToByteString 3 . BS.concat . map certificateToByteString

certificateToByteString :: Certificate -> BS.ByteString
certificateToByteString (CertificateRaw crt) = lenBodyToByteString 3 crt

data CertificateRequest
	= CertificateRequest [ClientCertificateType]
		[(HashAlgorithm, SignatureAlgorithm)] [X509.DistinguishedName]
	| CertificateRequestRaw BS.ByteString
	deriving Show

instance B.Bytable CertificateRequest where
	fromByteString = evalByteStringM parseCertificateRequest
	toByteString = certificateRequestToByteString

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

certificateRequestToByteString :: CertificateRequest -> BS.ByteString
certificateRequestToByteString (CertificateRequest ccts hsas bss) = BS.concat [
	lenBodyToByteString 1 . BS.concat $
		map clientCertificateTypeToByteString ccts,
		toByteString hsas,
	lenBodyToByteString 2 . BS.concat $
		map (lenBodyToByteString 2 . encodeASN1' DER . flip toASN1 []) bss ]
certificateRequestToByteString (CertificateRequestRaw bs) = bs

data ClientCertificateType
	= ClientCertificateTypeRsaSign
	| ClientCertificateTypeRaw Word8
	deriving Show

parseClientCertificateType :: ByteStringM ClientCertificateType
parseClientCertificateType = either error id . byteStringToClientCertificateType <$> takeBS 1

instance B.Bytable ClientCertificateType where
	fromByteString = byteStringToClientCertificateType
	toByteString = clientCertificateTypeToByteString

byteStringToClientCertificateType :: BS.ByteString -> Either String ClientCertificateType
byteStringToClientCertificateType bs = case BS.unpack bs of
	[w] -> Right $ case w of
		1 -> ClientCertificateTypeRsaSign
		_ -> ClientCertificateTypeRaw w
	_ -> Left "Certificate.byteStringToClientCertificateType"

clientCertificateTypeToByteString :: ClientCertificateType -> BS.ByteString
clientCertificateTypeToByteString ClientCertificateTypeRsaSign = "\x01"
clientCertificateTypeToByteString (ClientCertificateTypeRaw w) = BS.pack [w]

data EncryptedPreMasterSecret
	= EncryptedPreMasterSecret { getEncryptedPreMasterSecret :: BS.ByteString }

instance Show EncryptedPreMasterSecret where
	show (EncryptedPreMasterSecret epms) = "(EncryptedPreMasterSecret " ++
		showKeyPMS epms ++ ")"

instance B.Bytable EncryptedPreMasterSecret where
	fromByteString = Right . EncryptedPreMasterSecret
	toByteString = encryptedPreMasterSecretToByteString

showKeyPMS :: BS.ByteString -> String
showKeyPMS = concatMap showH . BS.unpack

showH :: Word8 -> String
showH w = replicate (2 - length s) '0' ++ s
	where
	s = showHex w ""

encryptedPreMasterSecretToByteString :: EncryptedPreMasterSecret -> BS.ByteString
encryptedPreMasterSecretToByteString (EncryptedPreMasterSecret epms) = epms

data DigitallySigned
	= DigitallySigned (HashAlgorithm, SignatureAlgorithm) BS.ByteString
	| DigitallySignedRaw BS.ByteString
	deriving Show

instance B.Bytable DigitallySigned where
	fromByteString = evalByteStringM parseDigitallySigned
	toByteString = digitallySignedToByteString

parseDigitallySigned :: ByteStringM DigitallySigned
parseDigitallySigned = DigitallySigned
	<$> ((,) <$> parse <*> parse)
	<*> takeLen 2

digitallySignedToByteString :: DigitallySigned -> BS.ByteString
digitallySignedToByteString (DigitallySigned (ha, sa) bs) = BS.concat [
	toByteString ha,
	toByteString sa,
	lenBodyToByteString 2 bs ]
digitallySignedToByteString (DigitallySignedRaw bs) = bs
