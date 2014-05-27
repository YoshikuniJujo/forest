{-# LANGUAGE OverloadedStrings #-}

module TlsServer (
	TlsClient, openClient, withClient, checkName, getName,
	readRsaKey, readCertificateChain, readCertificateStore
) where

import Control.Applicative
import Control.Monad
import Control.Monad.IO.Class
import Control.Exception
import Data.Maybe
import Data.HandleLike
import Data.ASN1.Types
import Data.X509
import Data.X509.File
import Data.X509.Validation
import Data.X509.CertificateStore
import System.IO
import Content
import Fragment

import qualified Data.ByteString as BS
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA

version :: Version
version = Version 3 3

cipherSuite :: CipherSuite
cipherSuite = TLS_RSA_WITH_AES_128_CBC_SHA

compressionMethod :: CompressionMethod
compressionMethod = CompressionMethodNull

openClient :: Handle
	-> RSA.PrivateKey -> CertificateChain -> Maybe CertificateStore
	-> IO TlsClient
openClient h = ((runOpen h .) .) . handshake

withClient :: Handle
	-> RSA.PrivateKey -> CertificateChain -> Maybe CertificateStore
	-> (TlsClient -> IO a) -> IO a
withClient = (((flip bracket hlClose .) .) .) . openClient

handshake :: RSA.PrivateKey -> CertificateChain -> Maybe CertificateStore
	-> TlsIo [String]
handshake sk cc mcs = do
	cv <- clientHello
	serverHello cc mcs
	mpn <- maybe (return Nothing) ((Just <$>) . clientCertificate) mcs
	clientKeyExchange sk cv
	maybe (return ()) (certificateVerify . fst) mpn
	clientChangeCipherSuite
	clientFinished
	serverChangeCipherSuite
	serverFinished
	return $ maybe [] snd mpn

clientHello :: TlsIo Version
clientHello = do
	hs <- readHandshake $ \(Version mj _) -> mj == 3
	case hs of
		HandshakeClientHello (ClientHello vsn rnd _ css cms _) ->
			err vsn css cms >> setClientRandom rnd >> return vsn
		_ -> throwError $ Alert AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"TlsServer.clientHello: not client hello"
	where
	err vsn css cms
		| vsn < version = throwError $ Alert
			AlertLevelFatal AlertDescriptionProtocolVersion
			"TlsServer.clientHello: client version should 3.3 or more"
		| cipherSuite `notElem` css = throwError $ Alert
			AlertLevelFatal AlertDescriptionIllegalParameter
			"TlsServer.clientHello: no supported cipher suites"
		| compressionMethod `notElem` cms = throwError $ Alert
			AlertLevelFatal AlertDescriptionDecodeError
			"TlsServer.clientHello: no supported compression method"
		| otherwise = return ()

serverHello :: CertificateChain -> Maybe CertificateStore -> TlsIo ()
serverHello cc mcs = do
	sr <- Random <$> randomByteString 32
	setVersion version
	setServerRandom sr
	cacheCipherSuite cipherSuite
	let	sc = [mksh sr, cert]
		shd = mkHandshake HandshakeServerHelloDone
	writeContentList $ sc ++ maybe [] ((: []) . certReq) mcs ++ [shd]
	where
	mksh sr = mkHandshake . HandshakeServerHello $ ServerHello
		version sr (SessionId "") cipherSuite compressionMethod Nothing
	certReq = mkHandshake . HandshakeCertificateRequest
		. CertificateRequest
			[ClientCertificateTypeRsaSign]
			[(HashAlgorithmSha256, SignatureAlgorithmRsa)]
		. map (certIssuerDN . signedObject . getSigned) . listCertificates
	cert = mkHandshake $ HandshakeCertificate cc
	writeContentList cs = do
		let f = contentListToFragment cs
		updateSequenceNumber Client
		writeFragment f
		fragmentUpdateHash f

mkHandshake :: Handshake -> Content
mkHandshake = ContentHandshake version

clientCertificate :: CertificateStore -> TlsIo (RSA.PublicKey, [String])
clientCertificate cs = do
	hs <- readHandshake (== version)
	case hs of
		HandshakeCertificate cc@(CertificateChain (c : _)) ->
			case certPubKey $ getCertificate c of
				PubKeyRSA pub ->
					chk cc >> return (pub, names cc)
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
	names (CertificateChain (t : _)) = getNames $ getCertificate t
	names _ = error "names: bad certificate chain"
	chk cc = do
--		liftIO . putStrLn $ "NAMES: " ++ show (names cc)
		v <- liftIO $ validate HashSHA256 defaultHooks
			defaultChecks{ checkFQHN = False } cs vc ("", "") cc
		unless (null v) . throwError $ Alert
			AlertLevelFatal
			(selectAlert v)
			("Validate Failure: " ++ show v)
	selectAlert rs
		| Expired `elem` rs = AlertDescriptionCertificateExpired
		| InFuture `elem` rs = AlertDescriptionCertificateExpired
		| UnknownCA `elem` rs = AlertDescriptionUnknownCa
		| otherwise = AlertDescriptionCertificateUnknown

getNames :: Certificate -> [String]
getNames cert = maybe [] (: altNames) $ commonName >>= asn1CharacterToString
	where
	commonName = getDnElement DnCommonName $ certSubjectDN cert
	altNames = maybe [] toAltName . extensionGet $ certExtensions cert
	toAltName (ExtSubjectAltName names) = mapMaybe unAltName names
	unAltName (AltNameDNS s) = Just s
	unAltName _ = Nothing

clientKeyExchange :: RSA.PrivateKey -> Version -> TlsIo ()
clientKeyExchange sk (Version cvmjr cvmnr) = do
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
		pms <- decryptRSA sk epms
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

certificateVerify :: RSA.PublicKey -> TlsIo ()
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

clientChangeCipherSuite :: TlsIo ()
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

clientFinished :: TlsIo ()
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

serverChangeCipherSuite :: TlsIo ()
serverChangeCipherSuite = do
	writeFragment . contentToFragment $
		ContentChangeCipherSpec version ChangeCipherSpec
	flushCipherSuite Server

serverFinished :: TlsIo ()
serverFinished = writeFragment . contentToFragment .
	ContentHandshake version . HandshakeFinished =<< finishedHash Server

readHandshake :: (Version -> Bool) -> TlsIo Handshake
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

readContent :: (Version -> Bool) -> TlsIo Content
readContent vc = do
	c <- getContent (readBufferContentType vc) (readByteString (== version))
		<* updateSequenceNumber Client
	fragmentUpdateHash $ contentToFragment c
	return c

readCertificateChain :: FilePath -> IO CertificateChain
readCertificateChain = (CertificateChain <$>) . readSignedObject

readRsaKey :: FilePath -> IO RSA.PrivateKey
readRsaKey fp = do [PrivKeyRSA sk] <- readKeyFile fp; return sk

readCertificateStore :: [FilePath] -> IO CertificateStore
readCertificateStore fps =
	makeCertificateStore . concat <$> mapM readSignedObject fps
