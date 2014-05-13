module Certificate (
	X509.CertificateChain,
	parseCertificateChain,
	certificateChainToByteString
) where

import Prelude hiding (concat)

import Control.Applicative

import qualified Data.X509 as X509

import ByteStringMonad
-- import ToByteString

data Certificate
	= CertificateRaw ByteString
	deriving Show

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
	lenBodyToByteString 3 . concat . map certificateToByteString

parseCertificate :: ByteStringM Certificate
parseCertificate = CertificateRaw <$> takeLen 3

certificateToByteString :: Certificate -> ByteString
certificateToByteString (CertificateRaw crt) = lenBodyToByteString 3 crt
