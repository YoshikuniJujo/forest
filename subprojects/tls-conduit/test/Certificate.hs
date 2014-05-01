module Certificate (
	X509.CertificateChain,
	certificateChain,
	certificateChainToByteString,

	CertificateList,
	certificateList,
	certificateListToByteString,
) where

import qualified Data.ByteString as BS
import qualified Data.X509 as X509

import Parts
import Tools

data CertificateChain
	= CertificateChain X509.CertificateChain
	deriving Show

certificateChainToByteString :: X509.CertificateChain -> BS.ByteString
certificateChainToByteString cc =
	certificateListToByteString $ encode cc

certificateChain :: BS.ByteString -> Either String (X509.CertificateChain, BS.ByteString)
certificateChain src = do
	(c, rest) <- certificateList src
	case decode c of
		Right cc -> return (cc, rest)
		Left (n, err) -> Left $ show n ++ " : " ++ err

type CertificateList = [Certificate]

certificateListToByteString :: CertificateList -> BS.ByteString
certificateListToByteString = listToByteString 3 certificateToByteString

certificateList :: BS.ByteString -> Either String (CertificateList, BS.ByteString)
certificateList = list 3 certificate

data Certificate
	= Certificate BS.ByteString
	deriving Show

certificateToByteString :: Certificate -> BS.ByteString
certificateToByteString (Certificate bs) = bodyToBS 3 bs

certificate :: BS.ByteString -> Either String (Certificate, BS.ByteString)
certificate src = do
	(body, rest) <- getBody 3 src
	return (Certificate body, rest)

certificateListToCertificateChainRaw :: CertificateList -> X509.CertificateChainRaw
certificateListToCertificateChainRaw =
	X509.CertificateChainRaw . map (\(Certificate c) -> c)

certificateChainRawToCertificateList :: X509.CertificateChainRaw -> CertificateList
certificateChainRawToCertificateList (X509.CertificateChainRaw ccr) =
	map Certificate ccr

decode :: CertificateList -> Either (Int, String) X509.CertificateChain
decode = X509.decodeCertificateChain . certificateListToCertificateChainRaw

encode :: X509.CertificateChain -> CertificateList
encode = certificateChainRawToCertificateList . X509.encodeCertificateChain
