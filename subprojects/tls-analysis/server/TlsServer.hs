{-# LANGUAGE OverloadedStrings, TypeFamilies, PackageImports #-}

module TlsServer (
	ValidateHandle(..),
	TlsClient, openClient, withClient,
	evalClient,
	checkName, getName,
	CipherSuite(..), CipherSuiteKeyEx(..), CipherSuiteMsgEnc(..),

	DH.SecretKey,
) where

import Control.Applicative
import Control.Monad
import Control.Exception
import Data.Maybe
import Data.List
import Data.HandleLike
import Data.ASN1.Types
import Data.X509
import Data.X509.Validation
import Data.X509.CertificateStore
import System.IO
import Content
import Fragment

import "monads-tf" Control.Monad.State

import "crypto-random" Crypto.Random

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Crypto.Types.PubKey.ECC as ECDSA
import qualified Crypto.Types.PubKey.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA

import qualified DiffieHellman as DH

import qualified EcDhe as ECDHE

import Control.Concurrent.STM

version :: Version
version = Version 3 3

sessionId :: SessionId
sessionId = SessionId ""

cipherSuite' :: [CipherSuite] -> [CipherSuite] -> Maybe CipherSuite
cipherSuite' csssv csscl = case find (`elem` csscl) csssv of
	Just cs -> Just cs
	_ -> if CipherSuite RSA AES_128_CBC_SHA `elem` csscl
		then Just $ CipherSuite RSA AES_128_CBC_SHA
		else Nothing

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

openClientIo :: DH.SecretKey sk =>
	Handle -> [CipherSuite] ->
	(RSA.PrivateKey, CertificateChain) -> (sk, CertificateChain) ->
	Maybe CertificateStore -> IO TlsClient
openClientIo h css (pk, cc) ecks mcs = do
	ep <- createEntropyPool
	(tc, ts) <- openClient h css (pk, cc) ecks mcs `runClient`
		(cprgCreate ep :: SystemRNG)
	tstv <- atomically $ newTVar ts
	return $ TlsClient tc tstv

withClient :: DH.SecretKey sk => Handle -> [CipherSuite] ->
	RSA.PrivateKey -> CertificateChain ->
	(sk, CertificateChain) -> Maybe CertificateStore -> (TlsClient -> IO a) ->
	IO a
withClient h css pk cc ecks mcs =
	bracket (openClientIo h css (pk, cc) ecks mcs) hlClose

evalClient :: (Monad m, CPRG g) => StateT (TlsClientState g) m a -> g -> m a
evalClient s g = fst `liftM` runClient s g

runClient :: (Monad m, CPRG g) =>
	StateT (TlsClientState g) m a -> g -> m (a, TlsClientState g)
runClient s g = s `runStateT` initialTlsState g

openClient :: (DH.SecretKey sk, ValidateHandle h, CPRG g) =>
	h -> [CipherSuite] ->
	(RSA.PrivateKey, CertificateChain) -> (sk, CertificateChain) ->
	Maybe CertificateStore ->
	HandleMonad (TlsClientConst h g) (TlsClientConst h g)
openClient h css (pk, cc) ecks mcs = runOpenSt h (helloHandshake css pk cc ecks mcs)

curve :: ECDHE.Curve
curve = fst (DH.generateBase undefined () :: (ECDHE.Curve, SystemRNG))

helloHandshake :: (DH.SecretKey sk, CPRG gen, ValidateHandle h) =>
 	[CipherSuite] ->  RSA.PrivateKey -> CertificateChain ->
 	(sk, CertificateChain) -> Maybe CertificateStore -> TlsIo h gen [String]
helloHandshake css sk cc (pkec, ccec) mcs = do
	cv <- hello css cc ccec
	cs <- getCipherSuite
	case cs of
		Just (CipherSuite RSA _) -> handshake False NoDH cv sk sk mcs
		Just (CipherSuite DHE_RSA _) -> handshake True DH.dhparams cv sk sk mcs
		Just (CipherSuite ECDHE_RSA _) -> handshake True curve cv sk sk mcs
		Just (CipherSuite ECDHE_ECDSA _) -> handshake True curve cv pkec undefined mcs
		_ -> error "bad"

hello :: (HandleLike h, CPRG gen) =>
	[CipherSuite] -> CertificateChain -> CertificateChain -> TlsIo h gen Version
hello csssv cc ccec = do
	(cv, css) <- clientHello
	serverHello csssv css cc ccec
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

	{-
handshake :: (DH.Base b, DH.SecretKey sk, CPRG gen, HandleLike h) =>
	Bool -> b -> Version -> sk ->
	RSA.PrivateKey -> Maybe CertificateStore -> TlsIo h gen [String]
handshake :: (DH.Base b, DH.SecretKey sk, CPRG gen) =>
	Bool -> b -> Version -> sk ->
	RSA.PrivateKey -> Maybe CertificateStore -> TlsIo Handle gen [String]
	-}
handshake :: (DH.Base b, DH.SecretKey sk, CPRG gen, ValidateHandle h) =>
	Bool -> b -> Version -> sk ->
	RSA.PrivateKey -> Maybe CertificateStore -> TlsIo h gen [String]
handshake isdh ps cv sks skd mcs = do
	h <- getHandle
	getCipherSuite >>= lift . lift . hlDebug h . BSC.pack . (++ "\n") . show
	pn <- if not isdh then return $ error "bad" else do
		gen <- getRandomGen
		let (pn, gen') = DH.generateSecret gen ps
		putRandomGen gen'
		return pn
	when isdh $ serverKeyExchange sks ps pn
	serverToHelloDone mcs
	mpn <- maybe (return Nothing) ((Just `liftM`) . clientCertificate) mcs
	dhe <- isEphemeralDH
	if dhe then DH.rcvClientKeyExchange ps pn cv else clientKeyExchange skd cv
	maybe (return ()) (certificateVerify . fst) mpn
	clientChangeCipherSuite
	clientFinished
	serverChangeCipherSuite
	serverFinished
	return $ maybe [] snd mpn

clientHello :: HandleLike h => TlsIo h gen (Version, [CipherSuite])
clientHello = do
	hs <- readHandshake $ \(Version mj _) -> mj == 3
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

serverHello :: (HandleLike h, CPRG gen) =>
	[CipherSuite] -> [CipherSuite] ->
	CertificateChain -> CertificateChain -> TlsIo h gen ()
serverHello csssv css cc ccec = do
	sr <- Random `liftM` randomByteString 32
	setVersion version
	setServerRandom sr
	case cipherSuite' csssv css of
		Just cs -> cacheCipherSuite cs
		_ -> throwError $ Alert
			AlertLevelFatal AlertDescriptionIllegalParameter
			"TlsServer.clientHello: no supported cipher suites"
	mcs <- getCipherSuite
	let (cs, cccc) = case mcs of
		Just c@(CipherSuite ECDHE_ECDSA _) -> (c, ccec)
		Just c -> (c, cc)
		_ -> error "bad"
--	liftIO . putStrLn $ "CIPHER SUITE: " ++ show cs
	((>>) <$> writeFragment <*> fragmentUpdateHash) . contentListToFragment .
		map (ContentHandshake version) $ catMaybes [
		Just . HandshakeServerHello $ ServerHello version sr sessionId
			cs compressionMethod Nothing,
		Just $ HandshakeCertificate cccc ]

serverKeyExchange :: HandleLike h => (DH.Base b, DH.SecretKey sk, CPRG gen) =>
	sk -> b -> DH.Secret b -> TlsIo h gen ()
serverKeyExchange sk ps pn = do
	dh <- isEphemeralDH
	Just rsr <- getServerRandom
	when dh $ DH.sndServerKeyExchange ps pn sk rsr

serverToHelloDone :: (HandleLike h, CPRG gen) =>
	Maybe CertificateStore -> TlsIo h gen ()
serverToHelloDone mcs =
	((>>) <$> writeFragment <*> fragmentUpdateHash) . contentListToFragment .
		map (ContentHandshake version) $ catMaybes [
		case mcs of
			Just cs -> Just . HandshakeCertificateRequest
				. CertificateRequest
					[clientCertificateType]
					[clientCertificateAlgorithm]
				. map (certIssuerDN . signedObject . getSigned)
				$ listCertificates cs
			_ -> Nothing,
		Just HandshakeServerHelloDone]

class Monad m => ValidateM m where
	vldt :: CertificateStore -> CertificateChain -> m [FailedReason]

instance ValidateM IO where
	vldt cs = validate
		HashSHA256 defaultHooks validationChecks cs validationCache ("", "")

class Validate v where
	type ValidateMonad v
	vldt' :: v -> CertificateStore -> CertificateChain ->
		ValidateMonad v [FailedReason]

data IoValidate = IoValidate deriving Show

instance Validate IoValidate where
	type ValidateMonad IoValidate = IO
	vldt' _ cs = validate
		HashSHA256 defaultHooks validationChecks cs validationCache ("", "")

type family HandleValidate h
type instance HandleValidate Handle = IoValidate

class HandleLike h => ValidateHandle h where
	vldt'' :: h -> CertificateStore -> CertificateChain ->
		HandleMonad h [FailedReason]

instance ValidateHandle Handle where
	vldt'' _ cs = validate
		HashSHA256 defaultHooks validationChecks cs validationCache ("", "")

clientCertificate :: ValidateHandle h => CertificateStore -> TlsIo h gen (PubKey, [String])
clientCertificate cs = do
	hs <- readHandshake (== version)
	h <- getHandle
	case hs of
		HandshakeCertificate cc@(CertificateChain (c : _)) ->
			case certPubKey $ getCertificate c of
				pub -> chk h cc >> return (pub, names cc)
		_ -> throwError $ Alert AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"TlsServer.clientCertificate: not certificate"
	where
	chk h cc = do
		rs <- lift .lift $ vldt'' h cs cc
		unless (null rs) . throwError $ Alert AlertLevelFatal
			(selectAlert rs)
			("TlsServer.clientCertificate: Validate Failure: "
				++ show rs)
		return undefined
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

clientKeyExchange :: (HandleLike h, CPRG gen) =>
	RSA.PrivateKey -> Version -> TlsIo h gen ()
clientKeyExchange sk (Version cvmjr cvmnr) = do
	h <- getHandle
	hs <- readHandshake (== version)
	case hs of
		HandshakeClientKeyExchange (EncryptedPreMasterSecret epms_) -> do
			let epms = BS.drop 2 epms_
			r <- randomByteString 46
			pms <- mkpms epms `catchError` const (return $ dummy r)
			lift . lift . hlDebug h $ "PRE MASTER SECRET: " `BS.append`
				BSC.pack (show pms) `BS.append` "\n"
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
			[pmsvmjr, pmsvmnr] ->
				unless (pmsvmjr == cvmjr && pmsvmnr == cvmnr) $
					throwError "bad: version"
			_ -> throwError "bad: never occur"
		return pms

certificateVerify :: HandleLike h => PubKey -> TlsIo h gen ()
certificateVerify (PubKeyRSA pub) = do
--	liftIO . putStrLn $ "VERIFY WITH RSA"
	hash0 <- clientVerifyHash pub
	hs <- readHandshake (== version)
	case hs of
		HandshakeCertificateVerify (DigitallySigned a s) -> do
			chk a
			let hash1 = RSA.ep pub s
			unless (hash1 == hash0) . throwError $ Alert
				AlertLevelFatal
				AlertDescriptionDecryptError $
				"client authentification failed "
--				++ show hash1 ++ " " ++ show hash0
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
certificateVerify (PubKeyECDSA ECDSA.SEC_p256r1 pnt) = do
--	liftIO . putStrLn $ "VERIFY WITH ECDSA"
	hash0 <- clientVerifyHashEc
--	liftIO . putStrLn $ "CLIENT VERIFY HASH: " ++ show hash0
	hs <- readHandshake (== version)
	case hs of
		HandshakeCertificateVerify (DigitallySigned a s) -> do
			chk a
			unless (ECDSA.verify id (pub pnt) (ECDHE.decodeSignature s) hash0) . throwError $ Alert
				AlertLevelFatal
				AlertDescriptionDecryptError
				"ECDSA: client authentification failed"
		_ -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"Not Certificate Verify"
	where
	point s = let 
		(x, y) = BS.splitAt 32 $ BS.drop 1 s in
		ECDSA.Point
			(DH.byteStringToInteger x)
			(DH.byteStringToInteger y)
	pub = ECDSA.PublicKey ECDHE.secp256r1 . point
	chk a = case a of
		(HashAlgorithmSha256, SignatureAlgorithmEcdsa) -> return ()
		_ -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionDecodeError
			("Not implement such algorithm: " ++ show a)
certificateVerify p = throwError $ Alert AlertLevelFatal
	AlertDescriptionUnsupportedCertificate
	("TlsServer.clientCertificate: " ++ "not implemented: " ++ show p)

clientChangeCipherSuite :: HandleLike h => TlsIo h gen ()
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

clientFinished :: HandleLike h => TlsIo h gen ()
clientFinished = do
	fhc <- finishedHash Client
--	liftIO . putStrLn $ "FINISHED HASH: " ++ show fhc
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

serverChangeCipherSuite :: (HandleLike h, CPRG gen) => TlsIo h gen ()
serverChangeCipherSuite = do
	writeFragment . contentToFragment $
		ContentChangeCipherSpec version ChangeCipherSpec
	flushCipherSuite Server

serverFinished :: (HandleLike h, CPRG gen) => TlsIo h gen ()
serverFinished = writeFragment . contentToFragment .
	ContentHandshake version . HandshakeFinished =<< finishedHash Server

readHandshake :: HandleLike h => (Version -> Bool) -> TlsIo h gen Handshake
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

readContent :: HandleLike h => (Version -> Bool) -> TlsIo h gen Content
readContent vc = do
	c <- const `liftM` getContent (readBufferContentType vc) (readByteString (== version))
		`ap` updateSequenceNumber Client
	fragmentUpdateHash $ contentToFragment c
	return c
