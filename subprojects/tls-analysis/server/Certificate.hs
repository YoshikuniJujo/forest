{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Certificate (
	CertificateRequest(..), certificateRequest,
	ClientCertificateType(..),
	ClientKeyExchange(..),
	DigitallySigned(..),
) where

import Prelude hiding (concat)

import Control.Applicative
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.Types
import Numeric
import Data.Word
import Data.Word.Word24

import qualified Data.ByteString as BS
import SignHashAlgorithm

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
	B.addLen (undefined :: Word24) . BS.concat . map certificateToByteString

certificateToByteString :: Certificate -> BS.ByteString
certificateToByteString (CertificateRaw crt) = B.addLen (undefined :: Word24) crt

data CertificateRequest
	= CertificateRequest [ClientCertificateType]
		[(HashAlgorithm, SignatureAlgorithm)] [X509.DistinguishedName]
	| CertificateRequestRaw BS.ByteString
	deriving Show

instance B.Bytable CertificateRequest where
	fromByteString = B.evalBytableM parseCertificateRequest'
	toByteString = certificateRequestToByteString

parseCertificateRequest' :: B.BytableM CertificateRequest
parseCertificateRequest' = do
	cctsl <- B.take 1
	ccts <- B.list cctsl $ B.take 1
	hasasl <- B.take 2
	hasas <- B.list hasasl $ (,) <$> B.take 1 <*> B.take 1
	dnsl <- B.take 2
	dns <- B.list dnsl $ do
		bs <- B.take =<< B.take 2
		asn1 <- either (fail . show) return $ decodeASN1' DER bs
		either (fail . show) (return . fst) $ fromASN1 asn1
	return $ CertificateRequest ccts hasas dns

certificateRequestToByteString :: CertificateRequest -> BS.ByteString
certificateRequestToByteString (CertificateRequest ccts hasas bss) = BS.concat [
	B.addLen (undefined :: Word8) . BS.concat $
		map clientCertificateTypeToByteString ccts,
		B.toByteString (fromIntegral $ 2 * length hasas :: Word16),
		BS.concat $ concatMap (\(ha, sa) -> [B.toByteString ha, B.toByteString sa]) hasas,
	B.addLen (undefined :: Word16) . BS.concat $
		map (B.addLen (undefined :: Word16) . encodeASN1' DER . flip toASN1 []) bss ]
certificateRequestToByteString (CertificateRequestRaw bs) = bs

data ClientCertificateType
	= ClientCertificateTypeRsaSign
	| ClientCertificateTypeEcdsaSign
	| ClientCertificateTypeRaw Word8
	deriving Show

instance B.Bytable ClientCertificateType where
	fromByteString = byteStringToClientCertificateType
	toByteString = clientCertificateTypeToByteString

byteStringToClientCertificateType :: BS.ByteString -> Either String ClientCertificateType
byteStringToClientCertificateType bs = case BS.unpack bs of
	[w] -> Right $ case w of
		1 -> ClientCertificateTypeRsaSign
		64 -> ClientCertificateTypeEcdsaSign
		_ -> ClientCertificateTypeRaw w
	_ -> Left "Certificate.byteStringToClientCertificateType"

clientCertificateTypeToByteString :: ClientCertificateType -> BS.ByteString
clientCertificateTypeToByteString ClientCertificateTypeRsaSign = "\x01"
clientCertificateTypeToByteString ClientCertificateTypeEcdsaSign = "\x40"
clientCertificateTypeToByteString (ClientCertificateTypeRaw w) = BS.pack [w]

data ClientKeyExchange = ClientKeyExchange { getClientKeyExchange :: BS.ByteString }

instance Show ClientKeyExchange where
	show (ClientKeyExchange epms) = "(ClientKeyExchange " ++
		showKeyPMS epms ++ ")"

instance B.Bytable ClientKeyExchange where
	fromByteString = Right . ClientKeyExchange
	toByteString = encryptedPreMasterSecretToByteString

showKeyPMS :: BS.ByteString -> String
showKeyPMS = concatMap showH . BS.unpack

showH :: Word8 -> String
showH w = replicate (2 - length s) '0' ++ s
	where
	s = showHex w ""

encryptedPreMasterSecretToByteString :: ClientKeyExchange -> BS.ByteString
encryptedPreMasterSecretToByteString (ClientKeyExchange epms) = epms

data DigitallySigned
	= DigitallySigned (HashAlgorithm, SignatureAlgorithm) BS.ByteString
	| DigitallySignedRaw BS.ByteString
	deriving Show

instance B.Bytable DigitallySigned where
	fromByteString = B.evalBytableM parseDigitallySigned
	toByteString = digitallySignedToByteString

parseDigitallySigned :: B.BytableM DigitallySigned
parseDigitallySigned = DigitallySigned
	<$> ((,) <$> B.take 1 <*> B.take 1)
	<*> (B.take =<< B.take 2)

digitallySignedToByteString :: DigitallySigned -> BS.ByteString
digitallySignedToByteString (DigitallySigned (ha, sa) bs) = BS.concat [
	B.toByteString ha,
	B.toByteString sa,
	B.addLen (undefined :: Word16) bs ]
digitallySignedToByteString (DigitallySignedRaw bs) = bs

certificateRequest ::
	[ClientCertificateType] -> [(HashAlgorithm, SignatureAlgorithm)] ->
	X509.CertificateStore -> CertificateRequest
certificateRequest cct cca =
	CertificateRequest cct cca
		. map (X509.certIssuerDN . X509.signedObject . X509.getSigned)
		. X509.listCertificates
