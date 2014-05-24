{-# LANGUAGE OverloadedStrings #-}

module TlsServer (
	TlsClient, openClient,
	readRsaKey, readCertificateChain, readCertificateStore) where

import Control.Applicative
import Control.Monad
import Control.Monad.IO.Class
import qualified Data.ByteString as BS
import Data.X509
import Data.X509.File
import Data.X509.Validation
import Data.X509.CertificateStore
import System.IO
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA

import Content
import Fragment

version :: Version
version = Version 3 3

mkhs :: Handshake -> Content
mkhs = ContentHandshake version

openClient :: Handle -> RSA.PrivateKey ->
	CertificateChain -> Maybe (String, CertificateStore) -> IO TlsClient
openClient cl pk = (runOpen cl pk .) . handshake

handshake :: CertificateChain -> Maybe (String, CertificateStore) -> TlsIo Content ()
handshake cc mcs = do
	cv <- clientHello
	serverHello cc $ snd <$> mcs
	mpub <- maybe (return Nothing) ((Just <$>) . uncurry clientCertificate) mcs
	clientKeyExchange cv
	maybe (return ()) certificateVerify mpub
	clientChangeCipherSuite
	clientFinished
	serverChangeCipherSuite
	serverFinished

clientHello :: TlsIo Content Version
clientHello = do
	hs <- readHandshake $ \(Version mj _) -> mj == 3
	case hs of
		HandshakeClientHello ch@(ClientHello vsn rnd _ _ _ _) ->
			setClientRandom rnd >> err ch >> return vsn
		_ -> throwError "Not Client Hello"
	where
	err (ClientHello vsn _ _ css cms _)
		| vsn < version = throwError emCVersion
		| TLS_RSA_WITH_AES_128_CBC_SHA `notElem` css = throwError emCSuite
		| CompressionMethodNull `notElem` cms = throwError emCMethod
		| otherwise = return ()
	err _ = throwError "Never occur"

emCVersion, emCSuite, emCMethod :: String
emCVersion = "Client Version should 3.3 or more"
emCSuite = "No supported Cipher Suites"
emCMethod = "No supported Compression Method"

serverHello :: CertificateChain -> Maybe CertificateStore -> TlsIo Content ()
serverHello cc mcs = do
	sr <- Random <$> randomByteString 32
	setVersion version
	setServerRandom sr
	cacheCipherSuite TLS_RSA_WITH_AES_128_CBC_SHA
	writeContentList $ [mksh sr, cert] ++ maybe [] ((: []) . certReq) mcs
		++ [ContentHandshake version HandshakeServerHelloDone]
	where
	mksh sr = mkhs . HandshakeServerHello $ ServerHello version sr
		(SessionId "")
		TLS_RSA_WITH_AES_128_CBC_SHA
		CompressionMethodNull Nothing
	certReq = mkhs . HandshakeCertificateRequest
		. CertificateRequest
			[ClientCertificateTypeRsaSign]
			[(HashAlgorithmSha256, SignatureAlgorithmRsa)]
		. map (certIssuerDN . signedObject . getSigned) . listCertificates
	cert = mkhs $ HandshakeCertificate cc

clientCertificate ::
	HostName -> CertificateStore -> TlsIo Content RSA.PublicKey
clientCertificate hn cs = do
	hs <- readHandshake (== version)
	case hs of
		HandshakeCertificate cc@(CertificateChain (c : _)) -> do
			case certPubKey $ getCertificate c of
				PubKeyRSA pub -> chk cc >> return pub
				p -> throwError $ "Not implemented: " ++ show p
		_ -> throwError "Not Certificate"
	where
	vc = ValidationCache
		(\_ _ _ -> return ValidationCacheUnknown) (\_ _ _ -> return ())
	chk cc = do
		v <- liftIO $ validateDefault cs vc (hn, "") cc
		unless (null v) . throwError $ "Validate Failure: " ++ show v

clientKeyExchange :: Version -> TlsIo Content ()
clientKeyExchange (Version cvmjr cvmnr) = do
	hs <- readHandshake (== version)
	case hs of
		HandshakeClientKeyExchange (EncryptedPreMasterSecret epms) -> do
			r <- randomByteString 46
			pms <- mkpms epms `catchError` const (return $ dummy r)
			generateKeys pms
		_ -> throwError "Not Client Key Exchange"
	where
	dummy r = cvmjr `BS.cons` cvmnr `BS.cons` r
	mkpms epms = do
		pms <- decryptRSA epms
		case BS.uncons pms of
			Just (pmsvmjr, pmstail) -> case BS.uncons pmstail of
				Just (pmsvmnr, _) -> do
					unless (pmsvmjr == cvmjr &&
						pmsvmnr == cvmnr) $
						throwError "bad: version"
					unless (BS.length pms == 48) $
						throwError "bad: length"
					return pms
				_ -> throwError "bad length"
			_ -> throwError "bad length"

certificateVerify :: RSA.PublicKey -> TlsIo Content ()
certificateVerify pub = do
	hash0 <- clientVerifyHash pub
	hs <- readHandshake (== version)
	case hs of
		HandshakeCertificateVerify (DigitallySigned a s) -> do
			chk a
			let hash1 = RSA.ep pub s
			unless (hash1 == hash0) $
				throwError "client authentificatin failed"
		_ -> throwError "Not Certificate Verify"
	where
	chk a = case a of
		(HashAlgorithmSha256, SignatureAlgorithmRsa) -> return ()
		_ -> throwError $ "Not implement such algorithm: " ++ show a

clientChangeCipherSuite :: TlsIo Content ()
clientChangeCipherSuite = do
	cnt <- readContent
	case cnt of
		ContentChangeCipherSpec v ChangeCipherSpec -> do
			unless (v == version) $ throwError "bad version"
			flushCipherSuite Client
		_ -> throwError "Not Change Cipher Spec"

clientFinished :: TlsIo Content ()
clientFinished = do
	fhc <- finishedHash Client
	cnt <- readContent
	case cnt of
		ContentHandshake v (HandshakeFinished f) -> do
			unless (v == version) $ throwError "bad version"
			unless (f == fhc) $ throwError "Finished error"
		_ -> throwError "Not Finished"

serverChangeCipherSuite :: TlsIo Content ()
serverChangeCipherSuite = do
	writeFragment . contentToFragment $
		ContentChangeCipherSpec version ChangeCipherSpec
	flushCipherSuite Server

serverFinished :: TlsIo Content ()
serverFinished = writeFragment . contentToFragment .
	ContentHandshake version . HandshakeFinished =<< finishedHash Server

readHandshake :: (Version -> Bool) -> TlsIo Content Handshake
readHandshake ck = do
	cnt <- readContent
	case cnt of
		ContentHandshake v hs
			| ck v -> return hs
			| otherwise -> throwError "Not supported layer version"
		_ -> throwError "Not Handshake"

readContent :: TlsIo Content Content
readContent = do
	c <- getContent readBufferContentType (readByteString (== version))
		<* updateSequenceNumber Client
	fragmentUpdateHash $ contentToFragment c
	return c

writeContentList :: [Content] -> TlsIo Content ()
writeContentList cs = do
	let f = contentListToFragment cs
	updateSequenceNumber Client
	writeFragment f
	fragmentUpdateHash f

readCertificateChain :: FilePath -> IO CertificateChain
readCertificateChain = (CertificateChain <$>) . readSignedObject

readRsaKey :: FilePath -> IO RSA.PrivateKey
readRsaKey fp = do [PrivKeyRSA pk] <- readKeyFile fp; return pk

readCertificateStore :: [FilePath] -> IO CertificateStore
readCertificateStore fps =
	makeCertificateStore . concat <$> mapM readSignedObject fps
