{-# LANGUAGE OverloadedStrings #-}

module TlsServer (
	TlsClient, openClient,
	readRsaKey, readCertificateChain, readCertificateStore) where

import Control.Applicative
import Control.Monad
import Control.Monad.IO.Class
import qualified Data.ByteString as BS
import Data.Maybe
import Data.ASN1.Types
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
	liftIO $ print hs
	case hs of
		HandshakeClientHello ch@(ClientHello vsn rnd _ _ _ _) ->
			setClientRandom rnd >> err ch >> return vsn
		_ -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"Not Client Hello"
	where
	err (ClientHello vsn _ _ css cms _)
		| vsn < version = throwError emCVersion
		| TLS_RSA_WITH_AES_128_CBC_SHA `notElem` css = throwError emCSuite
		| CompressionMethodNull `notElem` cms = throwError emCMethod
		| otherwise = return ()
	err _ = throwError "Never occur"

emCVersion, emCSuite, emCMethod :: Alert
emCVersion = Alert
	AlertLevelFatal
	AlertDescriptionProtocolVersion
	"Client Version should 3.3 or more"
emCSuite = Alert
	AlertLevelFatal
	AlertDescriptionIllegalParameter
	"No supported Cipher Suites"
emCMethod = Alert
	AlertLevelFatal
	AlertDescriptionDecodeError
	"No supported Compression Method"

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
		HandshakeCertificate cc@(CertificateChain (c : _)) ->
			case certPubKey $ getCertificate c of
				PubKeyRSA pub -> chk cc >> return pub
				p -> throwError $ Alert
					AlertLevelFatal
					AlertDescriptionUnsupportedCertificate
					("Not implemented: " ++ show p)
		_ -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"Not Certificate"
	where
	vc = ValidationCache
		(\_ _ _ -> return ValidationCacheUnknown) (\_ _ _ -> return ())
	chk cc@(CertificateChain (t : _)) = do
		liftIO . putStrLn $ "NAMES: " ++ show (getNames $ getCertificate t)
		v <- liftIO $ validate HashSHA256
			defaultHooks defaultChecks cs vc (hn, "") cc
		unless (null v) . throwError $ Alert
			AlertLevelFatal
			(selectAlert v)
			("Validate Failure: " ++ show v)
	chk _ = error "chk: bad certificate chain"
	selectAlert rs
		| Expired `elem` rs = AlertDescriptionCertificateExpired
		| InFuture `elem` rs = AlertDescriptionCertificateExpired
		| UnknownCA `elem` rs = AlertDescriptionUnknownCa
		| otherwise = AlertDescriptionCertificateUnknown

getNames :: Certificate -> (Maybe String, [String])
getNames cert = (commonName >>= asn1CharacterToString, altNames)
	where
	commonName = getDnElement DnCommonName $ certSubjectDN cert
	altNames = maybe [] toAltName $ extensionGet $ certExtensions cert
	toAltName (ExtSubjectAltName names) = catMaybes $ map unAltName names
	unAltName (AltNameDNS s) = Just s
	unAltName _ = Nothing

clientKeyExchange :: Version -> TlsIo Content ()
clientKeyExchange (Version cvmjr cvmnr) = do
	hs <- readHandshake (== version)
	case hs of
		HandshakeClientKeyExchange (EncryptedPreMasterSecret epms) -> do
			r <- randomByteString 46
			pms <- mkpms epms `catchError` const (return $ dummy r)
			generateKeys pms
		_ -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"Not Client Key Exchange"
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
			unless (hash1 == hash0) . throwError $ Alert
				AlertLevelFatal
				AlertDescriptionDecryptError
				"client authentification failed"
		_ -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"Not Certificate Verify"
	where
	chk a = case a of
		(HashAlgorithmSha256, SignatureAlgorithmRsa) -> return ()
		_ -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionDecodeError
			("Not implement such algorithm: " ++ show a)

clientChangeCipherSuite :: TlsIo Content ()
clientChangeCipherSuite = do
	cnt <- readContent (== version)
	case cnt of
		ContentChangeCipherSpec v ChangeCipherSpec -> do
			unless (v == version) . throwError $ Alert
				AlertLevelFatal
				AlertDescriptionProtocolVersion
				"bad version"
			flushCipherSuite Client
		_ -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"Not Change Cipher Spec"

clientFinished :: TlsIo Content ()
clientFinished = do
	fhc <- finishedHash Client
	cnt <- readContent (== version)
	case cnt of
		ContentHandshake v (HandshakeFinished f) -> do
			unless (v == version) . throwError $ Alert
				AlertLevelFatal
				AlertDescriptionProtocolVersion
				"bad version"
			unless (f == fhc) . throwError $ Alert
				AlertLevelFatal
				AlertDescriptionDecryptError
				"Finished error"
		_ -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"Not Finished"

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
	cnt <- readContent ck
	case cnt of
		ContentHandshake v hs
			| ck v -> return hs
			| otherwise -> throwError $ Alert
				AlertLevelFatal
				AlertDescriptionProtocolVersion
				"Not supported layer version"
		_ -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionUnexpectedMessage "Not Handshake"

readContent :: (Version -> Bool) -> TlsIo Content Content
readContent vc = do
	c <- getContent (readBufferContentType vc) (readByteString (== version))
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
