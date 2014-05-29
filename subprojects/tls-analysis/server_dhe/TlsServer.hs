{-# LANGUAGE OverloadedStrings, PackageImports #-}

module TlsServer (
	TlsClient, openClient, withClient, checkName, getName,
	readRsaKey, readCertificateChain, readCertificateStore
) where

import System.IO.Unsafe
import "crypto-random" Crypto.Random

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

import Crypto.PubKey.DH

version :: Version
version = Version 3 3

sessionId :: SessionId
sessionId = SessionId ""

cipherSuite :: [CipherSuite] -> CipherSuite
cipherSuite css
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
	(cv, css) <- clientHello
	serverHello css cc mcs
	mpn <- maybe (return Nothing) ((Just <$>) . clientCertificate) mcs
	clientKeyExchange sk cv
	maybe (return ()) (certificateVerify . fst) mpn
	clientChangeCipherSuite
	clientFinished
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

(dhParams, dhPrivate) = unsafePerformIO $ do
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	let	(ps, g') = generateParams g 8 2
		(pr, g'') = generatePrivate g' ps
	return (ps, pr)
	

serverHello :: [CipherSuite] -> CertificateChain -> Maybe CertificateStore -> TlsIo ()
serverHello css cc mcs = do
	sr <- Random <$> randomByteString 32
--	g <- getRandomGen
--	let	(ps, g') = generateParams g 8 2
--		(pr, g'') = generatePrivate g' ps
	let	ske = HandshakeServerKeyExchange $ ServerKeyExchange
			dhParams (calculatePublic dhParams dhPrivate) 2 1 "hogeru" ""
	liftIO $ print ske
	liftIO $ print $ contentToFragment $ ContentHandshake version ske
--	setRandomGen g''
	setVersion version
	setServerRandom sr
	cacheCipherSuite $ cipherSuite css
	((>>) <$> writeFragment <*> fragmentUpdateHash) . contentListToFragment .
		map (ContentHandshake version) $ catMaybes [
		Just $ HandshakeServerHello $ ServerHello version sr sessionId
			(cipherSuite css) compressionMethod Nothing,
		Just $ HandshakeCertificate cc,
		case mcs of
			Just cs -> Just $ HandshakeCertificateRequest
				. CertificateRequest
					[clientCertificateType]
					[clientCertificateAlgorithm]
				. map (certIssuerDN . signedObject . getSigned)
				$ listCertificates cs
			_ -> Nothing,
		Just $ ske,
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
		HandshakeClientKeyExchange (EncryptedPreMasterSecret epms) -> do
			liftIO $ putStrLn $ "CLIENT KEY: " ++ show epms
			let pms = getShared dhParams dhPrivate $
				byteStringToPublicNumber epms
			generateKeys $ integerToByteString $ fromIntegral pms
			{-
			r <- randomByteString 46
			pms <- mkpms epms `catchError` const (return $ dummy r)
			generateKeys pms
			-}
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
				AlertDescriptionDecryptError $
				"Finished error:\n\t" ++
				show f ++ "\n\t" ++
				show fhc ++ "\n"
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
