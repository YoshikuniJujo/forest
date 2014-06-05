{-# LANGUAGE OverloadedStrings, TypeFamilies, PackageImports #-}

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

import "crypto-random" Crypto.Random

import qualified Data.ByteString as BS
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA

import qualified DiffieHellman as DH

import qualified EcDhe as ECDHE

version :: Version
version = Version 3 3

sessionId :: SessionId
sessionId = SessionId ""

cipherSuite :: [CipherSuite] -> CipherSuite
cipherSuite css
	| CipherSuite ECDHE_ECDSA AES_128_CBC_SHA256 `elem` css =
		CipherSuite ECDHE_ECDSA AES_128_CBC_SHA256
	| CipherSuite ECDHE_ECDSA AES_128_CBC_SHA `elem` css =
		CipherSuite ECDHE_ECDSA AES_128_CBC_SHA
	| CipherSuite ECDHE_RSA AES_128_CBC_SHA256 `elem` css =
		CipherSuite ECDHE_RSA AES_128_CBC_SHA256
	| CipherSuite ECDHE_RSA AES_128_CBC_SHA `elem` css =
		CipherSuite ECDHE_RSA AES_128_CBC_SHA
	| CipherSuite DHE_RSA AES_128_CBC_SHA256 `elem` css =
		CipherSuite DHE_RSA AES_128_CBC_SHA256
	| CipherSuite DHE_RSA AES_128_CBC_SHA `elem` css =
		CipherSuite DHE_RSA AES_128_CBC_SHA
	| CipherSuite RSA AES_128_CBC_SHA256 `elem` css =
		CipherSuite RSA AES_128_CBC_SHA256
	| otherwise = CipherSuite RSA AES_128_CBC_SHA

compressionMethod :: CompressionMethod
compressionMethod = CompressionMethodNull

clientCertificateType :: ClientCertificateType
clientCertificateType = ClientCertificateTypeRsaSign

clientCertificateAlgorithm :: (HashAlgorithm, SignatureAlgorithm)
clientCertificateAlgorithm = (HashAlgorithmSha256, SignatureAlgorithmRsa)

validationCache :: ValidationCache
validationCache = ValidationCache
	(\_ _ _ -> return ValidationCacheUnknown)
	(\_ _ _ -> return ())

validationChecks :: ValidationChecks
validationChecks = defaultChecks{ checkFQHN = False }

-- openClient :: Handle
--	-> RSA.PrivateKey -> CertificateChain -> Maybe CertificateStore
--	-> IO TlsClient
-- openClient h = ((runOpen h .) .) . helloHandshake
openClient h pk cc ecks mcs = runOpen h $ helloHandshake pk cc ecks mcs

-- withClient :: Handle
--	-> RSA.PrivateKey -> CertificateChain -> Maybe CertificateStore
--	-> (TlsClient -> IO a) -> IO a
-- withClient = (((flip bracket hlClose .) .) .) . openClient
withClient h pk cc ecks mcs act =
	bracket (openClient h pk cc ecks mcs) hlClose act

curve :: ECDHE.Curve
curve = fst (DH.generateBase undefined () :: (ECDHE.Curve, SystemRNG))

-- helloHandshake :: RSA.PrivateKey -> CertificateChain ->
--	Maybe CertificateStore -> TlsIo [String]
helloHandshake sk cc (pkec, ccec) mcs = do
	cv <- hello cc ccec
	cs <- getCipherSuite
	liftIO $ print cs
	case cs of
		Just (CipherSuite RSA _) -> handshake NoDH cv sk sk mcs
		Just (CipherSuite DHE_RSA _) -> handshake DH.dhparams cv sk sk mcs
		Just (CipherSuite ECDHE_RSA _) -> handshake curve cv sk sk mcs
		Just (CipherSuite ECDHE_ECDSA _) -> handshake curve cv pkec undefined mcs
		_ -> error "bad"

hello :: CertificateChain -> CertificateChain -> TlsIo Version
hello cc ccec = do
	(cv, css) <- clientHello
	serverHello css cc ccec
	return cv

data NoDH = NoDH deriving Show

instance DH.Base NoDH where
	type Param NoDH = ()
	type Secret NoDH = ()
	type Public NoDH = ()
	generateBase = undefined
	generateSecret = undefined
	calculatePublic = undefined
	calculateCommon = undefined
	encodeBase = undefined
	decodeBase = undefined
	encodePublic = undefined
	decodePublic = undefined

-- handshake :: DH.Base b =>
--	b -> Version -> RSA.PrivateKey -> Maybe CertificateStore -> TlsIo [String]
handshake :: (DH.Base b, DH.SecretKey sk) => b -> Version -> sk ->
	RSA.PrivateKey -> Maybe CertificateStore -> TlsIo [String]
handshake ps cv sks skd mcs = do
	pn <- liftIO $ DH.dhprivate ps
	serverKeyExchange sks ps pn
	serverToHelloDone mcs
	liftIO . putStrLn $ "server hello done"
	mpn <- maybe (return Nothing) ((Just <$>) . clientCertificate) mcs
	dhe <- isEphemeralDH
	liftIO . putStrLn $ "is ephemeral DH?: " ++ show dhe
	if dhe then DH.rcvClientKeyExchange ps pn cv else clientKeyExchange skd cv
	maybe (return ()) (certificateVerify . fst) mpn
	liftIO . putStrLn $ "client key exchange done"
	clientChangeCipherSuite
	liftIO . putStrLn $ "client change cipher suite done"
	clientFinished
	liftIO . putStrLn $ "client finished done"
	serverChangeCipherSuite
	serverFinished
	return $ maybe [] snd mpn

clientHello :: TlsIo (Version, [CipherSuite])
clientHello = do
	hs <- readHandshake $ \(Version mj _) -> mj == 3
	liftIO $ print hs
	case hs of
		HandshakeClientHello (ClientHello vsn rnd _ css cms _) ->
			err vsn css cms >> setClientRandom rnd >> return (vsn, css)
		_ -> throwError $ Alert AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"TlsServer.clientHello: not client hello"
	where
	err vsn css cms
		| vsn < version = throwError $ Alert
			AlertLevelFatal AlertDescriptionProtocolVersion
			"TlsServer.clientHello: client version should 3.3 or more"
		| CipherSuite RSA AES_128_CBC_SHA `notElem` css = throwError $ Alert
			AlertLevelFatal AlertDescriptionIllegalParameter
			"TlsServer.clientHello: no supported cipher suites"
		| compressionMethod `notElem` cms = throwError $ Alert
			AlertLevelFatal AlertDescriptionDecodeError
			"TlsServer.clientHello: no supported compression method"
		| otherwise = return ()

serverHello :: [CipherSuite] -> CertificateChain -> CertificateChain -> TlsIo ()
serverHello css cc ccec = do
	sr <- Random <$> randomByteString 32
	setVersion version
	setServerRandom sr
	cacheCipherSuite $ cipherSuite css
	cs <- getCipherSuite
	let cccc = case cs of
		Just (CipherSuite ECDHE_ECDSA _) -> ccec
		_ -> cc
--	liftIO . putStrLn $ "cs = " ++ show cs
--	liftIO . putStrLn $ "cccc = " ++ show cccc
	((>>) <$> writeFragment <*> fragmentUpdateHash) . contentListToFragment .
		map (ContentHandshake version) $ catMaybes [
		Just $ HandshakeServerHello $ ServerHello version sr sessionId
			(cipherSuite css) compressionMethod Nothing,
		Just $ HandshakeCertificate cccc ]

serverKeyExchange ::
	(DH.Base b, DH.SecretKey sk) => sk -> b -> DH.Secret b -> TlsIo ()
serverKeyExchange sk ps pn = do
	dh <- isEphemeralDH
	liftIO $ print dh
	Just rsr <- getServerRandom
	when dh $ DH.sndServerKeyExchange ps pn sk rsr

serverToHelloDone :: Maybe CertificateStore -> TlsIo ()
serverToHelloDone mcs = do
	((>>) <$> writeFragment <*> fragmentUpdateHash) . contentListToFragment .
		map (ContentHandshake version) $ catMaybes [
		case mcs of
			Just cs -> Just $ HandshakeCertificateRequest
				. CertificateRequest
					[clientCertificateType]
					[clientCertificateAlgorithm]
				. map (certIssuerDN . signedObject . getSigned)
				$ listCertificates cs
			_ -> Nothing,
		Just HandshakeServerHelloDone]

clientCertificate :: CertificateStore -> TlsIo (RSA.PublicKey, [String])
clientCertificate cs = do
	hs <- readHandshake (== version)
	case hs of
		HandshakeCertificate cc@(CertificateChain (c : _)) ->
			case certPubKey $ getCertificate c of
				PubKeyRSA pub -> chk cc >> return (pub, names cc)
				p -> throwError $ Alert AlertLevelFatal
					AlertDescriptionUnsupportedCertificate
					("TlsServer.clientCertificate: " ++
						"not implemented: " ++ show p)
		_ -> throwError $ Alert AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"TlsServer.clientCertificate: not certificate"
	where
	chk cc = do
		rs <- liftIO $ validate HashSHA256 defaultHooks validationChecks
			cs validationCache ("", "") cc
		unless (null rs) . throwError $ Alert AlertLevelFatal
			(selectAlert rs)
			("TlsServer.clientCertificate: Validate Failure: "
				++ show rs)
	selectAlert rs
		| Expired `elem` rs = AlertDescriptionCertificateExpired
		| InFuture `elem` rs = AlertDescriptionCertificateExpired
		| UnknownCA `elem` rs = AlertDescriptionUnknownCa
		| otherwise = AlertDescriptionCertificateUnknown
	names cc = maybe [] (: ans (crt cc)) $ cn (crt cc) >>= asn1CharacterToString
	cn = getDnElement DnCommonName . certSubjectDN
	ans = maybe [] (\(ExtSubjectAltName ns) -> mapMaybe uan ns)
		. extensionGet . certExtensions
	crt cc = case cc of
		CertificateChain (t : _) -> getCertificate t
		_ -> error "TlsServer.clientCertificate: empty certificate chain"
	uan (AltNameDNS s) = Just s
	uan _ = Nothing

clientKeyExchange :: RSA.PrivateKey -> Version -> TlsIo ()
clientKeyExchange sk (Version cvmjr cvmnr) = do
	hs <- readHandshake (== version)
	case hs of
		HandshakeClientKeyExchange (EncryptedPreMasterSecret epms_) -> do
			let epms = BS.drop 2 epms_
			r <- randomByteString 46
			pms <- mkpms epms `catchError` const (return $ dummy r)
			generateKeys pms
		_ -> throwError $ Alert AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"TlsServer.clientKeyExchange: not client key exchange"
	where
	dummy r = cvmjr `BS.cons` cvmnr `BS.cons` r
	mkpms epms = do
		pms <- decryptRSA sk epms
		unless (BS.length pms == 48) $ throwError "bad: length"
		case BS.unpack $ BS.take 2 pms of
			[pmsvmjr, pmsvmnr] -> do
				unless (pmsvmjr == cvmjr && pmsvmnr == cvmnr) $
					throwError "bad: version"
			_ -> throwError "bad: never occur"
		return pms

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
