{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts, PackageImports #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module TlsServer (
	CipherSuite(..), KeyExchange(..), BulkEncryption(..),
	ValidateHandle(..), SecretKey,
	run, openClient, checkName, clientName
) where

import Prelude hiding (read)

import Control.Applicative ((<$>))
import Control.Monad (when, unless, liftM)
import "monads-tf" Control.Monad.Error (throwError, catchError, lift)
import "monads-tf" Control.Monad.Error.Class (strMsg)
import Data.Maybe (catMaybes, mapMaybe, listToMaybe)
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

import HandshakeType (
	Handshake(..),
	ClientHello(..), ServerHello(..),
		SessionId(..),
		CipherSuite(..), KeyExchange(..), BulkEncryption(..),
		CompressionMethod(..), NamedCurve(..),
	CertificateRequest(..),
		ClientCertificateType(..),
		SignatureAlgorithm(..), HashAlgorithm(..),
	ClientKeyExchange(..),
	DigitallySigned(..) )
import TlsHandle (
	TlsM, Alert(..), AlertLevel(..), AlertDescription(..),
		run, withRandom, randomByteString,
	TlsHandle(..), Keys(..), ContentType(..),
		newHandle, tlsGetContentType, tlsGet, tlsPut,

	generateKeys_,

	flushCipherSuite, debugCipherSuite,
	finishedHash_, handshakeHash,

	Partner(..),
	)
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

curve :: ECDSA.Curve
curve = fst (generateBase undefined () :: (ECDSA.Curve, SystemRNG))

openClient :: (SecretKey sk, CPRG g, ValidateHandle h) =>
	h -> [CipherSuite] ->
	(RSA.PrivateKey, X509.CertificateChain) -> (sk, X509.CertificateChain) ->
	Maybe X509.CertificateStore -> TlsM h g (TlsHandle h g)
openClient h css (sk, cc) (pkec, ccec) mcs = do
	th <- newHandle h
	(cv, cs, cr, sr) <- hello th css cc ccec
	let CipherSuite ke _ = cs
	case ke of
		RSA -> handshake False th cs cr sr NoDH cv sk sk mcs
		DHE_RSA -> handshake True th cs cr sr dhparams cv sk sk mcs
		ECDHE_RSA -> handshake True th cs cr sr curve cv sk sk mcs
		ECDHE_ECDSA -> handshake True th cs cr sr curve cv pkec undefined mcs
		_ -> throwError "TlsServer.helloHandshake"

hello :: (HandleLike h, CPRG g) =>
	TlsHandle h g -> [CipherSuite] ->
	X509.CertificateChain -> X509.CertificateChain ->
	TlsM h g (Version, CipherSuite, BS.ByteString, BS.ByteString)
hello th csssv cc ccec = do
	(cv, css, cr) <- clientHello th
	(cs, sr) <- serverHello th csssv css cc ccec
	return (cv, cs, cr, sr)

handshake :: (Base b, B.Bytable b, SecretKey sk, CPRG g, ValidateHandle h,
		B.Bytable (Public b)) =>
	Bool -> TlsHandle h g -> CipherSuite ->
	BS.ByteString -> BS.ByteString -> b -> Version -> sk ->
	RSA.PrivateKey -> Maybe X509.CertificateStore -> TlsM h g (TlsHandle h g)
handshake isdh th cs cr sr ps cv sks skd mcs = do
	pn <- if not isdh then return $ error "bad" else
		withRandom $ flip generateSecret ps
	when isdh $ serverKeyExchange th cr sr sks ps pn
	serverToHelloDone th mcs
	mpn <- maybe (return Nothing) ((Just `liftM`) . clientCertificate th) mcs
	thk <- if isdh	then rcvClientKeyExchange th cs cr sr ps pn cv
			else clientKeyExchange th cs cr sr skd cv
	maybe (return ()) (certificateVerify thk . fst) mpn
	thcc <- clientChangeCipherSuite thk
	clientFinished thcc
	thsc <- serverChangeCipherSuite thcc
	serverFinished thsc
	return thsc { clientNames = maybe [] snd mpn }

clientHello :: (HandleLike h, CPRG g) =>
	TlsHandle h g -> TlsM h g (Version, [CipherSuite], BS.ByteString)
clientHello th = do
	hs <- readHandshake th
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

serverHello :: (HandleLike h, CPRG g) =>
	TlsHandle h g -> [CipherSuite] -> [CipherSuite] ->
	X509.CertificateChain -> X509.CertificateChain ->
	TlsM h g (CipherSuite, BS.ByteString)
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
	tlsPut th ct bs
	return (cs, sr)

serverKeyExchange :: (HandleLike h, SecretKey sk, CPRG g,
	Base b, B.Bytable b, B.Bytable (Public b)) =>
	TlsHandle h g -> BS.ByteString -> BS.ByteString ->
	sk -> b -> Secret b -> TlsM h g ()
serverKeyExchange th cr sr pk ps dhsk = do
	let	ske = HandshakeServerKeyExchange . serverKeyExchangeToByteString .
			addSign pk cr sr $
			ServerKeyExchange
				(B.toByteString ps)
				(B.toByteString $ calculatePublic ps dhsk)
				HashAlgorithmSha1 (signatureAlgorithm pk) "hogeru"
		cont = [ContentHandshake ske]
		(ct, bs) = contentListToByteString cont
	tlsPut th ct bs

serverToHelloDone :: (HandleLike h, CPRG g) =>
	TlsHandle h g -> Maybe X509.CertificateStore -> TlsM h g ()
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
	tlsPut th ct bs

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

clientCertificate :: (ValidateHandle h, CPRG g) =>
	TlsHandle h g -> X509.CertificateStore -> TlsM h g (X509.PubKey, [String])
clientCertificate th cs = do
	hs <- readHandshake th
	case hs of
		HandshakeCertificate cc@(X509.CertificateChain (c : _)) ->
			case X509.certPubKey $ X509.getCertificate c of
				pub -> chk cc >> return (pub, names cc)
		_ -> throwError $ Alert AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"TlsServer.clientCertificate: not certificate"
	where
	chk cc = do
		rs <- lift .lift $ validate (tlsHandle th) cs cc
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

clientKeyExchange :: (HandleLike h, CPRG g) =>
	TlsHandle h g -> CipherSuite -> BS.ByteString -> BS.ByteString ->
	RSA.PrivateKey -> Version -> TlsM h g (TlsHandle h g)
clientKeyExchange th cs cr sr sk (cvmjr, cvmnr) = do
	hs <- readHandshake th
	case hs of
		HandshakeClientKeyExchange (ClientKeyExchange epms_) -> do
			let epms = BS.drop 2 epms_
			r <- randomByteString 46
			pms <- mkpms epms `catchError` const (return $ dummy r)
			ks <- generateKeys cs cr sr pms
			return $ th { keys = ks }
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

certificateVerify :: (HandleLike h, CPRG g) =>
	TlsHandle h g -> X509.PubKey -> TlsM h g ()
certificateVerify th (X509.PubKeyRSA pub) = do
	debugCipherSuite th "RSA"
	hash0 <- rsaPadding pub `liftM` handshakeHash th
	hs <- readHandshake th
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
certificateVerify th (X509.PubKeyECDSA ECDSA.SEC_p256r1 pnt) = do
	debugCipherSuite th "ECDSA"
	hash0 <- handshakeHash th
	hs <- readHandshake th
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
certificateVerify _ p = throwError $ Alert AlertLevelFatal
	AlertDescriptionUnsupportedCertificate
	("TlsServer.clientCertificate: " ++ "not implemented: " ++ show p)

clientChangeCipherSuite :: (HandleLike h, CPRG g) =>
	TlsHandle h g -> TlsM h g (TlsHandle h g)
clientChangeCipherSuite th = do
	cnt <- readContent th
	case cnt of
		ContentChangeCipherSpec ChangeCipherSpec ->
			return $ flushCipherSuite Client th
		_ -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"Not Change Cipher Spec"

clientFinished :: (HandleLike h, CPRG g) => TlsHandle h g -> TlsM h g ()
clientFinished th = do
	fhc <- finishedHash th Client
	cnt <- readContent th
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

serverChangeCipherSuite :: (HandleLike h, CPRG g) =>
	TlsHandle h g -> TlsM h g (TlsHandle h g)
serverChangeCipherSuite th = do
	uncurry (tlsPut th) . contentToByteString $
		ContentChangeCipherSpec ChangeCipherSpec
	return $ flushCipherSuite Server th

serverFinished :: (HandleLike h, CPRG g) => TlsHandle h g -> TlsM h g ()
serverFinished th =
	uncurry (tlsPut th) . contentToByteString .
	ContentHandshake . HandshakeFinished =<< finishedHash th Server

readHandshake :: (HandleLike h, CPRG g) => TlsHandle h g -> TlsM h g Handshake
readHandshake th = do
	cnt <- readContent th
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

readContent :: (HandleLike h, CPRG g) => TlsHandle h g -> TlsM h g Content
readContent th =
	parseContent ((snd `liftM`) . tlsGet th) =<< tlsGetContentType th

parseContent :: Monad m => (Int -> m BS.ByteString) -> ContentType -> m Content
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

rcvClientKeyExchange ::
	(HandleLike h, Base b, B.Bytable (Public b), CPRG g) =>
	TlsHandle h g -> CipherSuite -> BS.ByteString -> BS.ByteString ->
	b -> Secret b -> Version -> TlsM h g (TlsHandle h g)
rcvClientKeyExchange th cs cr sr dhps dhpn (_cvmjr, _cvmnr) = do
	hs <- readHandshake th
	case hs of
		HandshakeClientKeyExchange (ClientKeyExchange epms) -> do
			let Right pms = calculateCommon dhps dhpn <$> B.fromByteString epms
			ks <- generateKeys cs cr sr pms
			return th { keys = ks }
		_ -> throwError $ Alert AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"TlsServer.clientKeyExchange: not client key exchange"

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

decryptRSA :: (HandleLike h, CPRG g) =>
	RSA.PrivateKey -> BS.ByteString -> TlsM h g BS.ByteString
decryptRSA sk e =
	either (throwError . strMsg . show) return =<<
	withRandom (\g -> RSA.decryptSafer g sk e)

generateKeys :: HandleLike h => CipherSuite ->
	BS.ByteString -> BS.ByteString -> BS.ByteString -> TlsM h g Keys
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

finishedHash :: HandleLike h => TlsHandle h g -> Partner -> TlsM h g BS.ByteString
finishedHash th partner = do
	let ms = kMasterSecret $ keys th
	sha256 <- handshakeHash th
	return $ finishedHash_ (partner == Client) ms sha256

checkName :: TlsHandle h g -> String -> Bool
checkName tc n = n `elem` clientNames tc

clientName :: TlsHandle h g -> Maybe String
clientName = listToMaybe . clientNames
