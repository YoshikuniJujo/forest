{-# LANGUAGE OverloadedStrings #-}

import Control.Applicative
import Data.X509
import Data.X509.Validation
import Data.X509.CertificateStore
import Data.X509.File
import Data.Maybe

main :: IO ()
main = do
	cs <- makeCertificateStore <$> readSignedObject "cacert.pem"
	cc@(CertificateChain scs) <- CertificateChain <$> readSignedObject "yoshikuni.crt"
	print $ getDnElement DnCommonName $ certSubjectDN $ head $ map getCertificate scs
	print $ maybe [] toAltName $ extensionGet $ certExtensions $ head $ map getCertificate scs
	validateDefault cs (ValidationCache query add) ("Yoshikuni", "Yoshio") cc >>= print

query :: ValidationCacheQueryCallback
query _ _ _ = return ValidationCacheUnknown

add :: ValidationCacheAddCallback
add _ _ _ = return ()

toAltName (ExtSubjectAltName names) = catMaybes $ map unAltName names

unAltName (AltNameDNS s) = Just s
unAltName _ = Nothing
