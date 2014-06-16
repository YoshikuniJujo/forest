{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts, PackageImports #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module TlsServer (
	evalClient, openClient, checkName, clientName,
	ValidateHandle(..), SecretKey,
	CipherSuite(..), KeyExchange(..), BulkEncryption(..),
) where

import Prelude hiding (read)

import Control.Applicative ((<$>))
import Control.Arrow
import Control.Monad
import "monads-tf" Control.Monad.Error.Class (strMsg)
import Data.Maybe (catMaybes, mapMaybe)
import Data.List (find)
import Data.Word (Word8, Word16)
import Data.HandleLike (HandleLike(..))
import System.IO (Handle)
import "crypto-random" Crypto.Random (CPRG, SystemRNG)

import qualified Data.ByteString as BS
import qualified Data.ASN1.Types as ASN1
import qualified Data.ASN1.Encoding as ASN1
import qualified Data.ASN1.BinaryEncoding as ASN1
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509
import qualified Data.X509.CertificateStore as X509
import qualified Codec.Bytable as B
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.PubKey.HashDescr as RSA
import qualified Crypto.Types.PubKey.ECC as ECDSA
import qualified Crypto.Types.PubKey.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.Hash.SHA1 as SHA1

import HandshakeType {- (
	Handshake(..),
	ClientHello(..), ServerHello(..),
		SessionId(..),
		CipherSuite(..), KeyExchange(..), BulkEncryption(..),
		CompressionMethod(..), NamedCurve(..),
	CertificateRequest(..),
		ClientCertificateType(..),
		SignatureAlgorithm(..), HashAlgorithm(..),
	ClientKeyExchange(..),
	DigitallySigned(..) ) -}

import HM hiding (cipherSuite)
import qualified HM
import KeyAgreement (Base(..), NoDH(..), secp256r1, dhparams)

type Version = (Word8, Word8)

version :: Version
version = (3, 3)

sessionId :: SessionId
sessionId = SessionId ""

cipherSuite :: [CipherSuite] -> [CipherSuite] -> Maybe CipherSuite
cipherSuite csssv csscl = case find (`elem` csscl) csssv of
	Just cs -> Just cs
	_ -> if CipherSuite RSA AES_128_CBC_SHA `elem` csscl
		then Just $ CipherSuite RSA AES_128_CBC_SHA
		else Nothing

compressionMethod :: CompressionMethod
compressionMethod = CompressionMethodNull

clientCertificateTypes :: [ClientCertificateType]
clientCertificateTypes = [
	ClientCertificateTypeRsaSign,
	ClientCertificateTypeEcdsaSign ]

clientCertificateAlgorithms :: [(HashAlgorithm, SignatureAlgorithm)]
clientCertificateAlgorithms = [
	(HashAlgorithmSha256, SignatureAlgorithmRsa),
	(HashAlgorithmSha256, SignatureAlgorithmEcdsa) ]

evalClient :: (HandleLike h, CPRG g) => HandshakeM h g a -> g -> HandleMonad h a
evalClient s g = fst `liftM` runClient s g

runClient :: (HandleLike h, CPRG g) =>
	HandshakeM h g a -> g -> HandleMonad h (a, TlsClientState h g)
runClient s g = do
	(Right ret, st') <- s `runHandshakeM` initialTlsStateWithClientZero g
	return (ret, st')

openClient :: (SecretKey sk, ValidateHandle h, CPRG g) => h -> [CipherSuite] ->
	(RSA.PrivateKey, X509.CertificateChain) -> (sk, X509.CertificateChain) ->
	Maybe X509.CertificateStore ->
	HandleMonad (TlsClientConst h g) (TlsClientConst h g)
openClient h css (pk, cc) ecks mcs =
	runOpen h (helloHandshake (mkTlsHandle h) css pk cc ecks mcs)

curve :: ECDSA.Curve
curve = fst (generateBase undefined () :: (ECDSA.Curve, SystemRNG))

helloHandshake :: (SecretKey sk, CPRG gen, ValidateHandle h) =>
	TlsHandle h ->
 	[CipherSuite] ->  RSA.PrivateKey -> X509.CertificateChain ->
 	(sk, X509.CertificateChain) -> Maybe X509.CertificateStore -> HandshakeM h gen ([String], Keys)
helloHandshake th css sk cc (pkec, ccec) mcs = do
	(cv, cs, cr, sr) <- hello th css cc ccec
	let CipherSuite ke _ = cs
	case ke of
		RSA -> handshake False th cs cr sr NoDH cv sk sk mcs
		DHE_RSA -> handshake True th cs cr sr dhparams cv sk sk mcs
		ECDHE_RSA -> handshake True th cs cr sr curve cv sk sk mcs
		ECDHE_ECDSA -> handshake True th cs cr sr curve cv pkec undefined mcs
		_ -> throwError "TlsServer.helloHandshake"

hello :: (HandleLike h, CPRG gen) =>
	TlsHandle h ->
	[CipherSuite] ->
	X509.CertificateChain -> X509.CertificateChain ->
	HandshakeM h gen (
		Version, CipherSuite, BS.ByteString, BS.ByteString)
hello th csssv cc ccec = do
	(cv, css, cr) <- clientHello th
	(cs, sr) <- serverHello th csssv css cc ccec
	return (cv, cs, cr, sr)

handshake ::
	(Base b, B.Bytable b, SecretKey sk, CPRG gen, ValidateHandle h,
		B.Bytable (Public b)) => Bool ->
	TlsHandle h -> CipherSuite ->
	BS.ByteString -> BS.ByteString ->
	b -> Version -> sk ->
	RSA.PrivateKey -> Maybe X509.CertificateStore ->
	HandshakeM h gen ([String], Keys)
handshake isdh th cs cr sr ps cv sks skd mcs = do
	pn <- if not isdh then return $ error "bad" else
		withRandom $ flip generateSecret ps
	when isdh $ serverKeyExchange th cr sr sks ps pn
	serverToHelloDone th mcs
	mpn <- maybe (return Nothing) ((Just `liftM`) . clientCertificate th) mcs
	ks <- if isdh	then rcvClientKeyExchange th cs cr sr ps pn cv
			else clientKeyExchange th cs cr sr skd cv
	maybe (return ()) (certificateVerify th ks . fst) mpn
	ks' <- clientChangeCipherSuite th ks
	clientFinished th ks'
	ks'' <- serverChangeCipherSuite th ks'
	serverFinished th ks''
	return (maybe [] snd mpn, ks'')

clientHello :: HandleLike h =>
	TlsHandle h ->
	HandshakeM h gen (Version, [CipherSuite], BS.ByteString)
clientHello th = do
	hs <- readHandshake th nullKeys $ \(mj, _) -> mj == 3
	case hs of
		HandshakeClientHello (ClientHello vsn rnd _ css cms _) ->
			err vsn css cms >> return (vsn, css, rnd)
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
	TlsHandle h ->
	[CipherSuite] -> [CipherSuite] ->
	X509.CertificateChain -> X509.CertificateChain ->
	HandshakeM h gen (CipherSuite, BS.ByteString)
serverHello th csssv css cc ccec = do
	sr <- randomByteString 32
	cs <- case cipherSuite csssv css of
		Just cs -> return cs
		_ -> throwError $ Alert
			AlertLevelFatal AlertDescriptionIllegalParameter
			"TlsServer.clientHello: no supported cipher suites"
	let CipherSuite ke _ = cs
	let	cccc = case ke of
			ECDHE_ECDSA -> ccec
			_ -> cc
		cont = map ContentHandshake $ catMaybes [
			Just . HandshakeServerHello $ ServerHello
				version sr sessionId
				cs compressionMethod Nothing,
			Just $ HandshakeCertificate cccc ]
		(ct, bs) = contentListToByteString cont
	writeByteString th nullKeys ct bs
	return (cs, sr)

serverKeyExchange :: (HandleLike h, SecretKey sk, CPRG gen,
	Base b, B.Bytable b, B.Bytable (Public b)) =>
	TlsHandle h ->
	BS.ByteString -> BS.ByteString ->
	sk -> b -> Secret b -> HandshakeM h gen ()
serverKeyExchange th cr sr pk ps dhsk = do
	let	ske = HandshakeServerKeyExchange . serverKeyExchangeToByteString .
			addSign pk cr sr $
			ServerKeyExchange
				(B.toByteString ps)
				(B.toByteString $ calculatePublic ps dhsk)
				HashAlgorithmSha1 (signatureAlgorithm pk) "hogeru"
		cont = [ContentHandshake ske]
		(ct, bs) = contentListToByteString cont
	writeByteString th nullKeys ct bs

serverToHelloDone :: (HandleLike h, CPRG gen) =>
	TlsHandle h ->
	Maybe X509.CertificateStore -> HandshakeM h gen ()
serverToHelloDone th mcs = do
	let	cont = map ContentHandshake $ catMaybes [
			case mcs of
				Just cs -> Just . HandshakeCertificateRequest
					. CertificateRequest
						clientCertificateTypes
						clientCertificateAlgorithms
					. map (X509.certIssuerDN . X509.signedObject . X509.getSigned)
					$ X509.listCertificates cs
				_ -> Nothing,
			Just HandshakeServerHelloDone]
		(ct, bs) = contentListToByteString cont
	writeByteString th nullKeys ct bs

class HandleLike h => ValidateHandle h where
	validate :: h -> X509.CertificateStore -> X509.CertificateChain ->
		HandleMonad h [X509.FailedReason]

instance ValidateHandle Handle where
	validate _ cs = X509.validate
		X509.HashSHA256 X509.defaultHooks validationChecks cs validationCache ("", "")

validationCache :: X509.ValidationCache
validationCache = X509.ValidationCache
	(\_ _ _ -> return X509.ValidationCacheUnknown)
	(\_ _ _ -> return ())

validationChecks :: X509.ValidationChecks
validationChecks = X509.defaultChecks { X509.checkFQHN = False }

clientCertificate :: ValidateHandle h =>
	TlsHandle h ->
	X509.CertificateStore -> HandshakeM h gen (X509.PubKey, [String])
clientCertificate th cs = do
	hs <- readHandshake th nullKeys (== (3, 3))
	case hs of
		HandshakeCertificate cc@(X509.CertificateChain (c : _)) ->
			case X509.certPubKey $ X509.getCertificate c of
				pub -> chk cc >> return (pub, names cc)
		_ -> throwError $ Alert AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"TlsServer.clientCertificate: not certificate"
	where
	chk cc = do
		rs <- lift .lift $ validate (getHandle th) cs cc
		unless (null rs) . throwError $ Alert AlertLevelFatal
			(selectAlert rs)
			("TlsServer.clientCertificate: Validate Failure: "
				++ show rs)
		return undefined
	selectAlert rs
		| X509.Expired `elem` rs = AlertDescriptionCertificateExpired
		| X509.InFuture `elem` rs = AlertDescriptionCertificateExpired
		| X509.UnknownCA `elem` rs = AlertDescriptionUnknownCa
		| otherwise = AlertDescriptionCertificateUnknown
	names cc = maybe [] (: ans (crt cc)) $ cn (crt cc) >>=
		ASN1.asn1CharacterToString
	cn = X509.getDnElement X509.DnCommonName . X509.certSubjectDN
	ans = maybe [] (\(X509.ExtSubjectAltName ns) -> mapMaybe uan ns)
		. X509.extensionGet . X509.certExtensions
	crt cc = case cc of
		X509.CertificateChain (t : _) -> X509.getCertificate t
		_ -> error "TlsServer.clientCertificate: empty certificate chain"
	uan (X509.AltNameDNS s) = Just s
	uan _ = Nothing

clientKeyExchange :: (HandleLike h, CPRG gen) =>
	TlsHandle h -> CipherSuite ->
	BS.ByteString -> BS.ByteString ->
	RSA.PrivateKey -> Version -> HandshakeM h gen Keys
clientKeyExchange th cs cr sr sk (cvmjr, cvmnr) = do
	hs <- readHandshake th nullKeys (== (3, 3))
	case hs of
		HandshakeClientKeyExchange (ClientKeyExchange epms_) -> do
			let epms = BS.drop 2 epms_
			r <- randomByteString 46
			pms <- mkpms epms `catchError` const (return $ dummy r)
			generateKeys cs cr sr pms
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

rsaPadding :: RSA.PublicKey -> BS.ByteString -> BS.ByteString
rsaPadding pub bs =
	case RSA.padSignature (RSA.public_size pub) $
			RSA.digestToASN1 RSA.hashDescrSHA256 bs of
		Right pd -> pd
		Left msg -> error $ show msg

certificateVerify :: HandleLike h =>
	TlsHandle h -> Keys -> X509.PubKey -> HandshakeM h gen ()
certificateVerify th ks (X509.PubKeyRSA pub) = do
	debugCipherSuite th ks "RSA"
	hash0 <- rsaPadding pub `liftM` handshakeHash
	hs <- readHandshake th nullKeys (== (3, 3))
	case hs of
		HandshakeCertificateVerify (DigitallySigned a s) -> do
			chk a
			let hash1 = RSA.ep pub s
			unless (hash1 == hash0) . throwError $ Alert
				AlertLevelFatal
				AlertDescriptionDecryptError
				"client authentification failed "
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
certificateVerify th ks (X509.PubKeyECDSA ECDSA.SEC_p256r1 pnt) = do
	debugCipherSuite th ks "ECDSA"
	hash0 <- handshakeHash
	hs <- readHandshake th nullKeys (== (3, 3))
	case hs of
		HandshakeCertificateVerify (DigitallySigned a s) -> do
			chk a
			unless (ECDSA.verify id (pub pnt)
				(either error id $ B.fromByteString s) hash0) .
					throwError $ Alert
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
			(either error id $ B.fromByteString x)
			(either error id $ B.fromByteString y)
	pub = ECDSA.PublicKey secp256r1 . point
	chk a = case a of
		(HashAlgorithmSha256, SignatureAlgorithmEcdsa) -> return ()
		_ -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionDecodeError
			("Not implement such algorithm: " ++ show a)
certificateVerify _ _ p = throwError $ Alert AlertLevelFatal
	AlertDescriptionUnsupportedCertificate
	("TlsServer.clientCertificate: " ++ "not implemented: " ++ show p)

clientChangeCipherSuite :: HandleLike h =>
	TlsHandle h -> Keys -> HandshakeM h gen Keys
clientChangeCipherSuite th ks = do
	cnt <- readContent th nullKeys (== (3, 3))
	case cnt of
		ContentChangeCipherSpec ChangeCipherSpec ->
			return $ flushCipherSuite Client ks
		_ -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"Not Change Cipher Spec"

clientFinished :: HandleLike h =>
	TlsHandle h -> Keys -> HandshakeM h gen ()
clientFinished th ks = do
	fhc <- finishedHash ks Client
	cnt <- readContent th ks (== (3, 3))
	case cnt of
		ContentHandshake (HandshakeFinished f) ->
			unless (f == fhc) . throwError $ Alert
				AlertLevelFatal
				AlertDescriptionDecryptError
				"Finished error"
		_ -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"Not Finished"

serverChangeCipherSuite :: (HandleLike h, CPRG gen) =>
	TlsHandle h -> Keys -> HandshakeM h gen Keys
serverChangeCipherSuite th ks = do
	uncurry (writeByteString th nullKeys) . contentToByteString $
		ContentChangeCipherSpec ChangeCipherSpec
	return $ flushCipherSuite Server ks

serverFinished :: (HandleLike h, CPRG gen) =>
	TlsHandle h -> Keys -> HandshakeM h gen ()
serverFinished th ks = uncurry (writeByteString th ks) . contentToByteString .
	ContentHandshake . HandshakeFinished =<< finishedHash ks Server

readHandshake :: HandleLike h => TlsHandle h -> Keys ->
	(Version -> Bool) -> HandshakeM h gen Handshake
readHandshake ht ks ck = do
	cnt <- readContent ht ks ck
	case cnt of
		ContentHandshake hs
			| True -> return hs
			| otherwise -> throwError $ Alert
				AlertLevelFatal
				AlertDescriptionProtocolVersion
				"Not supported layer version"
		_ -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionUnexpectedMessage "Not Handshake"

readContent :: HandleLike h => TlsHandle h -> Keys ->
	(Version -> Bool) -> HandshakeM h gen Content
readContent th ks vc =
	getContent (readContentType th ks vc) (readByteString th ks (== (3, 3)))

rcvClientKeyExchange :: (HandleLike h, Base b, B.Bytable (Public b)) =>
	TlsHandle h -> CipherSuite ->
	BS.ByteString -> BS.ByteString ->
	b -> Secret b -> Version -> HandshakeM h gen Keys
rcvClientKeyExchange th cs cr sr dhps dhpn (_cvmjr, _cvmnr) = do
	hs <- readHandshake th nullKeys (== (3, 3))
	case hs of
		HandshakeClientKeyExchange (ClientKeyExchange epms) -> do
			let Right pms = calculateCommon dhps dhpn <$> B.fromByteString epms
			generateKeys cs cr sr pms
		_ -> throwError $ Alert AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"TlsServer.clientKeyExchange: not client key exchange"

getContent :: Monad m =>
	m ContentType -> (Int -> m (ContentType, BS.ByteString)) -> m Content
getContent rct rd = do
	ct <- rct
	parseContent ((snd `liftM`) . rd) ct

parseContent :: Monad m =>
	(Int -> m BS.ByteString) -> ContentType -> m Content
parseContent rd ContentTypeChangeCipherSpec =
	(ContentChangeCipherSpec . either error id . B.fromByteString) `liftM` rd 1
parseContent rd ContentTypeAlert =
	((\[al, ad] -> ContentAlert al ad) . BS.unpack) `liftM` rd 2
parseContent rd ContentTypeHandshake = ContentHandshake `liftM` do
	t <- rd 1
	len <- rd 3
	body <- rd . either error id $ B.fromByteString len
	return . either error id . B.fromByteString $ BS.concat [t, len, body]
parseContent _ ContentTypeApplicationData = undefined
parseContent _ _ = undefined

contentListToByteString :: [Content] -> (ContentType, BS.ByteString)
contentListToByteString cs = let fs@((ct, _) : _) = map contentToByteString cs in
	(ct, BS.concat $ map snd fs)

contentToByteString :: Content -> (ContentType, BS.ByteString)
contentToByteString (ContentChangeCipherSpec ccs) =
	(ContentTypeChangeCipherSpec, B.toByteString ccs)
contentToByteString (ContentAlert al ad) = (ContentTypeAlert, BS.pack [al, ad])
contentToByteString (ContentHandshake hss) =
	(ContentTypeHandshake, B.toByteString hss)

data Content
	= ContentChangeCipherSpec ChangeCipherSpec
	| ContentAlert Word8 Word8
	| ContentHandshake Handshake
	deriving Show

data ChangeCipherSpec
	= ChangeCipherSpec
	| ChangeCipherSpecRaw Word8
	deriving Show

instance B.Bytable ChangeCipherSpec where
	fromByteString bs = case BS.unpack bs of
			[1] -> Right ChangeCipherSpec
			[ccs] -> Right $ ChangeCipherSpecRaw ccs
			_ -> Left "Content.hs: instance Bytable ChangeCipherSpec"
	toByteString ChangeCipherSpec = BS.pack [1]
	toByteString (ChangeCipherSpecRaw ccs) = BS.pack [ccs]

addSign :: SecretKey sk =>
	sk -> BS.ByteString -> BS.ByteString -> ServerKeyExchange -> ServerKeyExchange
addSign sk cr sr (ServerKeyExchange ps ys ha sa _) = let
	sn = sign sk SHA1.hash $ BS.concat [cr, sr, ps, ys] in
	ServerKeyExchange ps ys ha sa sn

data ServerKeyExchange
	= ServerKeyExchange BS.ByteString BS.ByteString HashAlgorithm SignatureAlgorithm BS.ByteString
	deriving Show

serverKeyExchangeToByteString :: ServerKeyExchange -> BS.ByteString
serverKeyExchangeToByteString
	(ServerKeyExchange params dhYs hashA sigA sn) =
	BS.concat [
		params, dhYs, B.toByteString hashA, B.toByteString sigA,
		B.addLength (undefined :: Word16) sn ]

instance B.Bytable ECDSA.Curve where
	fromByteString = undefined
	toByteString = encodeCurve

encodeCurve :: ECDSA.Curve -> BS.ByteString
encodeCurve c
	| c == secp256r1 =
		B.toByteString NamedCurve `BS.append` B.toByteString Secp256r1
	| otherwise = error "TlsServer.encodeCurve: not implemented"

data EcCurveType
	= ExplicitPrime
	| ExplicitChar2
	| NamedCurve
	| EcCurveTypeRaw Word8
	deriving Show

instance B.Bytable EcCurveType where
	fromByteString = undefined
	toByteString ExplicitPrime = BS.pack [1]
	toByteString ExplicitChar2 = BS.pack [2]
	toByteString NamedCurve = BS.pack [3]
	toByteString (EcCurveTypeRaw w) = BS.pack [w]

instance B.Bytable ECDSA.Signature where
	fromByteString = decodeSignature
	toByteString = undefined

decodeSignature :: BS.ByteString -> Either String ECDSA.Signature
decodeSignature bs = case ASN1.decodeASN1' ASN1.DER bs of
	Right [ASN1.Start ASN1.Sequence,
		ASN1.IntVal r,
		ASN1.IntVal s,
		ASN1.End ASN1.Sequence] ->
		Right $ ECDSA.Signature r s
	Right _ -> Left "KeyExchange.decodeSignature"
	Left err -> Left $ "KeyExchange.decodeSignature: " ++ show err

class SecretKey sk where
	sign :: sk -> (BS.ByteString -> BS.ByteString) ->
		BS.ByteString -> BS.ByteString
	signatureAlgorithm :: sk -> SignatureAlgorithm

instance SecretKey ECDSA.PrivateKey where
	sign sk hs bs = let
		Just (ECDSA.Signature r s) = ECDSA.signWith 4649 sk hs bs in
		encodeEcdsaSign $ EcdsaSign 0x30 (2, r) (2, s)
	signatureAlgorithm _ = SignatureAlgorithmEcdsa

data EcdsaSign
	= EcdsaSign Word8 (Word8, Integer) (Word8, Integer)
	deriving Show

encodeEcdsaSign :: EcdsaSign -> BS.ByteString
encodeEcdsaSign (EcdsaSign t (rt, rb) (st, sb)) = BS.concat [
	BS.pack [t, len rbbs + len sbbs + 4],
	BS.pack [rt, len rbbs], rbbs,
	BS.pack [st, len sbbs], sbbs ]
	where
	len = fromIntegral . BS.length
	rbbs = B.toByteString rb
	sbbs = B.toByteString sb

instance SecretKey RSA.PrivateKey where
	sign sk hs bs = let
		h = hs bs
		a = [ASN1.Start ASN1.Sequence,
			ASN1.Start ASN1.Sequence,
			ASN1.OID [1, 3, 14, 3, 2, 26],
			ASN1.Null,
			ASN1.End ASN1.Sequence,
			ASN1.OctetString h,
			ASN1.End ASN1.Sequence]
		b = ASN1.encodeASN1' ASN1.DER a
		pd = BS.concat [
			"\x00\x01", BS.replicate (125 - BS.length b) 0xff,
			"\NUL", b ] in
		RSA.dp Nothing sk pd
	signatureAlgorithm _ = SignatureAlgorithmRsa

decryptRSA :: (HandleLike h, CPRG gen) =>
	RSA.PrivateKey -> BS.ByteString -> HandshakeM h gen BS.ByteString
decryptRSA pk e = eitherToError =<< withRandom (\gen -> RSA.decryptSafer gen pk e)

generateKeys :: HandleLike h => CipherSuite ->
	BS.ByteString -> BS.ByteString ->
	BS.ByteString -> HandshakeM h gen Keys
generateKeys cs cr sr pms = do
	let CipherSuite _ be = cs
	kl <- case be of
		AES_128_CBC_SHA -> return 20
		AES_128_CBC_SHA256 -> return 32
		_ -> throwError "bad"
	let Right (ms, cwmk, swmk, cwk, swk) = generateKeys_ kl cr sr pms
	return Keys {
		kCachedCipherSuite = cs,
		kClientCipherSuite = CipherSuite KE_NULL BE_NULL,
		kServerCipherSuite = CipherSuite KE_NULL BE_NULL,

		kMasterSecret = ms,
		kClientWriteMacKey = cwmk,
		kServerWriteMacKey = swmk,
		kClientWriteKey = cwk,
		kServerWriteKey = swk }

finishedHash :: HandleLike h => Keys -> Partner -> HandshakeM h gen BS.ByteString
finishedHash ks partner = do
	let ms = kMasterSecret ks
	sha256 <- handshakeHash
	return $ finishedHash_ (partner == Client) ms sha256

runOpen :: (HandleLike h, CPRG gen) => h ->
	HandshakeM h gen ([String], Keys) ->
	HandleMonad (TlsClientConst h gen) (TlsClientConst h gen)
-- runOpen cl opn = ErrorT $ StateT $ \s -> first Right `liftM` runOpenSt_ s cl opn
runOpen cl opn = handshakeM $ \s -> first Right `liftM` runOpenSt_ s cl opn

runOpenSt_ :: (HandleLike h, CPRG gen) => TlsClientState h gen ->
	h -> HandshakeM h gen ([String], Keys) ->
	HandleMonad h (TlsClientConst h gen, TlsClientState h gen)
runOpenSt_ s cl opn = do
	((ns, ks), s') <- runHm (mkTlsHandle cl) opn s
	let tc = TlsClientConst {
		clientId = clientIdZero,
		tlsHandle = cl,
		tlsNames = ns,
		keys = ks }
	return (tc, s')

-- runOpenSt__ :: (HandleLike h, CPRG gen) => h -> HandshakeM h gen

readContentType :: HandleLike h => TlsHandle h -> Keys ->
	((Word8, Word8) -> Bool) -> HandshakeM h gen ContentType
readContentType th ks vc = getContentType vc $ readFragment th ks

readByteString :: HandleLike h => TlsHandle h -> Keys ->
	((Word8, Word8) -> Bool) -> Int -> HandshakeM h gen (ContentType, BS.ByteString)
readByteString th ks vc n = do
	(ct, bs) <- buffered n $ do
		(t, v, b) <- readFragment th ks
		unless (vc v) . throwError $ Alert
			AlertLevelFatal
			AlertDescriptionProtocolVersion
			"Fragment.readByteString: bad Version"
		return (t, b)
	case ct of
		ContentTypeHandshake -> updateHash bs
		_ -> return ()
	return (ct, bs)

readFragment :: HandleLike h => TlsHandle h -> Keys ->
	HandshakeM h gen (ContentType, (Word8, Word8), BS.ByteString)
readFragment th ks = do
	ct <- (either error id . B.fromByteString) `liftM` read th 1
	[vmjr, vmnr] <- BS.unpack `liftM` read th 2
	let v = (vmjr, vmnr)
	ebody <- read th . either error id . B.fromByteString =<< read th 2
	when (BS.null ebody) $ throwError "readFragment: ebody is null"
	body <- tlsDecryptMessage ks ct ebody
	return (ct, v, body)

writeByteString :: (HandleLike h, CPRG gen) => TlsHandle h -> Keys ->
	ContentType -> BS.ByteString -> HandshakeM h gen ()
writeByteString th ks ct bs = do
	enc <- tlsEncryptMessage ks ct bs
	case ct of
		ContentTypeHandshake -> updateHash bs
		_ -> return ()
	write th $ BS.concat [
		B.toByteString ct,
		B.toByteString (3 :: Word8),
		B.toByteString (3 :: Word8),
		B.toByteString (fromIntegral $ BS.length enc :: Word16), enc ]

tlsEncryptMessage :: (HandleLike h, CPRG gen) => Keys ->
	ContentType -> BS.ByteString -> HandshakeM h gen BS.ByteString
tlsEncryptMessage Keys{ kServerCipherSuite = CipherSuite _ BE_NULL } _ msg =
	return msg
tlsEncryptMessage ks ct msg = do
	let	CipherSuite _ be = HM.cipherSuite Server ks
		wk = kServerWriteKey ks
		mk = kServerWriteMacKey ks
	sn <- updateSequenceNumber Server ks
	hs <- case be of
		AES_128_CBC_SHA -> return hashSha1
		AES_128_CBC_SHA256 -> return hashSha256
		_ -> throwError "bad"
	let enc = encryptMessage hs wk mk sn
		(B.toByteString ct `BS.append` "\x03\x03") msg
	withRandom enc

tlsDecryptMessage :: HandleLike h => Keys ->
	ContentType -> BS.ByteString -> HandshakeM h gen BS.ByteString
tlsDecryptMessage Keys{ kClientCipherSuite = CipherSuite _ BE_NULL } _ enc =
	return enc
tlsDecryptMessage ks ct enc = do
	let	CipherSuite _ be = HM.cipherSuite Client ks
		wk = kClientWriteKey ks
		mk = kClientWriteMacKey ks
	sn <- updateSequenceNumber Client ks
	hs <- case be of
		AES_128_CBC_SHA -> return hashSha1
		AES_128_CBC_SHA256 -> return hashSha256
		_ -> throwError "bad"
	eitherToError $ decryptMessage hs wk mk sn
		(B.toByteString ct `BS.append` "\x03\x03") enc

eitherToError :: (Show msg, MonadError m, Error (ErrorType m)) => Either msg a -> m a
eitherToError = either (throwError . strMsg . show) return
