{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts, PackageImports,
	TupleSections #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module TlsServer (
	CipherSuite(..), KeyExchange(..), BulkEncryption(..),
	ValidateHandle(..), SecretKey,
	run, openClient, checkName, clientName
) where

import Prelude hiding (read)

import Control.Applicative ((<$>))
import Control.Monad (unless, liftM)
import "monads-tf" Control.Monad.Trans (lift)
import "monads-tf" Control.Monad.State (StateT, execStateT, get, put, modify)
import "monads-tf" Control.Monad.Error (throwError, catchError)
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
	TlsHandle(..), ContentType(..),
		newHandle, tlsGetContentType, tlsGet, tlsPut, generateKeys,
		cipherSuite, setCipherSuite, flushCipherSuite, debugCipherSuite,
	Partner(..), finishedHash, handshakeHash )
import KeyAgreement (Base(..), NoDH(..), secp256r1, dhparams)

type Version = (Word8, Word8)

version :: Version
version = (3, 3)

sessionId :: SessionId
sessionId = SessionId ""

cipherSuiteSel :: [CipherSuite] -> [CipherSuite] -> Maybe CipherSuite
cipherSuiteSel sv cl = case find (`elem` cl) sv of
	Just cs -> Just cs
	_ -> if CipherSuite RSA AES_128_CBC_SHA `elem` cl
		then Just $ CipherSuite RSA AES_128_CBC_SHA
		else Nothing

compressionMethod :: CompressionMethod
compressionMethod = CompressionMethodNull

clientCertificateTypes :: [ClientCertificateType]
clientCertificateTypes =
	[ClientCertificateTypeRsaSign, ClientCertificateTypeEcdsaSign]

clientCertificateAlgorithms :: [(HashAlgorithm, SignatureAlgorithm)]
clientCertificateAlgorithms = [
	(HashAlgorithmSha256, SignatureAlgorithmRsa),
	(HashAlgorithmSha256, SignatureAlgorithmEcdsa) ]

curve :: ECDSA.Curve
curve = fst (generateBase undefined () :: (ECDSA.Curve, SystemRNG))

type HandshakeM h g = StateT (TlsHandle h g) (TlsM h g)

tlsPut' :: (HandleLike h, CPRG g) =>
	ContentType -> BS.ByteString -> HandshakeM h g ()
tlsPut' ct bs = get >>= lift . \t -> tlsPut t ct bs

openClient :: (ValidateHandle h, CPRG g, SecretKey sk) =>
	h -> [CipherSuite] ->
	(RSA.PrivateKey, X509.CertificateChain) -> (sk, X509.CertificateChain) ->
	Maybe X509.CertificateStore -> TlsM h g (TlsHandle h g)
openClient h cssv (sk, cc) (esk, ecc) mcs = (newHandle h >>=) . execStateT $ do
	(cscl, cr, cv) <- clientHello
	(ke, sr) <- serverHello cssv cscl cc ecc
	mpk <- case ke of
		RSA -> keyExchange False cr cv sr NoDH sk sk mcs
		DHE_RSA -> keyExchange True cr cv sr dhparams sk undefined mcs
		ECDHE_RSA -> keyExchange True cr cv sr curve sk undefined mcs
		ECDHE_ECDSA -> keyExchange True cr cv sr curve esk undefined mcs
		_ -> throwError "TlsServer.openClient"
	certificateVerify mpk
	clientChangeCipherSpec
	clientFinished
	serverChangeCipherSpec
	serverFinished

keyExchange :: (ValidateHandle h, CPRG g, SecretKey sk,
	Base b, B.Bytable b, B.Bytable (Public b)) =>
	Bool -> BS.ByteString -> Version -> BS.ByteString -> b -> sk ->
	RSA.PrivateKey -> Maybe X509.CertificateStore ->
	HandshakeM h g (Maybe X509.PubKey)
keyExchange dh cr cv sr bs ssk rsk mcs = do
	msk <- serverKeyExchange dh cr sr bs ssk mcs
	mpk <- clientCertificate mcs
	clientKeyExchange cr cv sr rsk bs msk
	return mpk

clientHello :: (HandleLike h, CPRG g) =>
	HandshakeM h g ([CipherSuite], BS.ByteString, Version)
clientHello = do
	hs <- readHandshake'
	case hs of
		HandshakeClientHello (ClientHello vsn rnd _ css cms _) ->
			err vsn css cms >> return (css, rnd, vsn)
		_ -> throwError $ Alert AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"TlsServer.clientHello_: not client hello"
	where
	err vsn css cms
		| vsn < version = throwError $ Alert
			AlertLevelFatal AlertDescriptionProtocolVersion
			"TlsServer.clientHello_: client version should 3.3 or more"
		| CipherSuite RSA AES_128_CBC_SHA `notElem` css = throwError $ Alert
			AlertLevelFatal AlertDescriptionIllegalParameter
			"TlsServer.clientHello_: no supported cipher suites"
		| compressionMethod `notElem` cms = throwError $ Alert
			AlertLevelFatal AlertDescriptionDecodeError
			"TlsServer.clientHello_: no supported compression method"
		| otherwise = return ()

serverHello :: (HandleLike h, CPRG g) => [CipherSuite] -> [CipherSuite] ->
	X509.CertificateChain -> X509.CertificateChain ->
	HandshakeM h g (KeyExchange, BS.ByteString)
serverHello csssv css cc ccec = do
	sr <- lift $ randomByteString 32
	cs@(CipherSuite ke _) <- case cipherSuiteSel csssv css of
		Just cs -> return cs
		_ -> throwError $ Alert
			AlertLevelFatal AlertDescriptionIllegalParameter
			"TlsServer.clientHello_: no supported cipher suites"
	let	cccc = case ke of
			ECDHE_ECDSA -> ccec
			_ -> cc
		cont = map ContentHandshake $ catMaybes [
			Just . HandshakeServerHello $ ServerHello
				version sr sessionId
				cs compressionMethod Nothing,
			Just $ HandshakeCertificate cccc ]
	uncurry tlsPut' $ contentListToByteString cont
	modify $ setCipherSuite cs
	return (ke, sr)

serverKeyExchange :: (HandleLike h, CPRG g,
	Base b, B.Bytable b, B.Bytable (Public b), SecretKey sk) =>
	Bool -> BS.ByteString -> BS.ByteString -> b -> sk ->
	Maybe (X509.CertificateStore) -> HandshakeM h g (Maybe (Secret b))
serverKeyExchange dh cr sr b sks mcs = do
	msk <- if dh
		then do
			sk <- lift $ withRandom (generateSecret b)
			t <- get
			lift $ serverKeyExchange_ t cr sr sks b sk
			return $ Just sk
		else return Nothing
	get >>= lift . flip serverToHelloDone mcs
	return msk

serverKeyExchange_ :: (HandleLike h, SecretKey sk, CPRG g,
	Base b, B.Bytable b, B.Bytable (Public b)) =>
	TlsHandle h g -> BS.ByteString -> BS.ByteString ->
	sk -> b -> Secret b -> TlsM h g ()
serverKeyExchange_ th cr sr pk ps dhsk = do
	let	ske = HandshakeServerKeyExchange . serverKeyExchangeToByteString .
			addSign pk cr sr $
			ServerKeyExchange
				(B.toByteString ps)
				(B.toByteString $ calculatePublic ps dhsk)
				HashAlgorithmSha1 (signatureAlgorithm pk) "hogeru"
		cont = [ContentHandshake ske]
		(ct, bs) = contentListToByteString cont
	tlsPut th ct bs

serverToHelloDone' :: (HandleLike h, CPRG g) =>
	Maybe X509.CertificateStore -> HandshakeM h g ()
serverToHelloDone' = (get >>=) . lift . flip serverToHelloDone

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

clientCertificate :: (ValidateHandle h, CPRG g) =>
	Maybe X509.CertificateStore -> HandshakeM h g (Maybe X509.PubKey)
clientCertificate mcs = do
	t <- get
	mn <- lift $ maybe (return Nothing)
		((Just `liftM`) . clientCertificate_ t) mcs
	put t { clientNames = maybe [] snd mn }
	return $ fst <$> mn

clientKeyExchange :: (HandleLike h, CPRG g, Base b, B.Bytable (Public b)) =>
	BS.ByteString -> Version -> BS.ByteString -> RSA.PrivateKey ->
	b -> Maybe (Secret b) -> HandshakeM h g ()
clientKeyExchange cr cv sr rsk bs msk = get >>= \t -> (put =<<) . lift $
	case msk of
		Just sk -> ecClientKeyExchange t cr sr bs sk
		_ -> clientKeyExchange_ t cr cv sr rsk

certificateVerify :: (HandleLike h, CPRG g) =>
	Maybe X509.PubKey -> HandshakeM h g ()
certificateVerify mp = do
	t <- get
	lift $ maybe (return ()) (certificateVerify_ t) mp

clientChangeCipherSpec :: (HandleLike h, CPRG g) => HandshakeM h g ()
clientChangeCipherSpec = get >>= lift . clientChangeCipherSuite >>= put

clientFinished :: (HandleLike h, CPRG g) => HandshakeM h g ()
clientFinished = get >>= lift . clientFinished_

serverChangeCipherSpec :: (HandleLike h, CPRG g) => HandshakeM h g ()
serverChangeCipherSpec = get >>= lift . serverChangeCipherSuite >>= put

serverFinished :: (HandleLike h, CPRG g) => HandshakeM h g ()
serverFinished = get >>= lift . serverFinished_

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

clientCertificate_ :: (ValidateHandle h, CPRG g) =>
	TlsHandle h g -> X509.CertificateStore -> TlsM h g (X509.PubKey, [String])
clientCertificate_ th cs = do
	hs <- readHandshake th
	case hs of
		HandshakeCertificate cc@(X509.CertificateChain (c : _)) ->
			case X509.certPubKey $ X509.getCertificate c of
				pub -> chk cc >> return (pub, names cc)
		_ -> throwError $ Alert AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"TlsServer.clientCertificate_: not certificate"
	where
	chk cc = do
		rs <- lift .lift $ validate (tlsHandle th) cs cc
		unless (null rs) . throwError $ Alert AlertLevelFatal
			(selectAlert rs)
			("TlsServer.clientCertificate_: Validate Failure: "
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
		_ -> error "TlsServer.clientCertificate_: empty certificate chain"
	uan (X509.AltNameDNS s) = Just s
	uan _ = Nothing

clientKeyExchange_ :: (HandleLike h, CPRG g) =>
	TlsHandle h g -> BS.ByteString -> Version -> BS.ByteString ->
	RSA.PrivateKey -> TlsM h g (TlsHandle h g)
clientKeyExchange_ th cr (cvmjr, cvmnr) sr sk = do
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
	cs = cipherSuite th
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

certificateVerify_ :: (HandleLike h, CPRG g) =>
	TlsHandle h g -> X509.PubKey -> TlsM h g ()
certificateVerify_ th (X509.PubKeyRSA pub) = do
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
certificateVerify_ th (X509.PubKeyECDSA ECDSA.SEC_p256r1 pnt) = do
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
certificateVerify_ _ p = throwError $ Alert AlertLevelFatal
	AlertDescriptionUnsupportedCertificate
	("TlsServer.clientCertificate_: " ++ "not implemented: " ++ show p)

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

clientFinished_ :: (HandleLike h, CPRG g) => TlsHandle h g -> TlsM h g ()
clientFinished_ th = do
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

serverFinished_ :: (HandleLike h, CPRG g) => TlsHandle h g -> TlsM h g ()
serverFinished_ th =
	uncurry (tlsPut th) . contentToByteString .
	ContentHandshake . HandshakeFinished =<< finishedHash th Server

readHandshake' :: (HandleLike h, CPRG g) => HandshakeM h g Handshake
readHandshake' = get >>= lift . readHandshake

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

ecClientKeyExchange ::
	(HandleLike h, Base b, B.Bytable (Public b), CPRG g) =>
	TlsHandle h g -> BS.ByteString -> BS.ByteString ->
	b -> Secret b -> TlsM h g (TlsHandle h g)
ecClientKeyExchange th cr sr dhps dhpn = do
	hs <- readHandshake th
	case hs of
		HandshakeClientKeyExchange (ClientKeyExchange epms) -> do
			let Right pms = calculateCommon dhps dhpn <$> B.fromByteString epms
			ks <- generateKeys (cipherSuite th) cr sr pms
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

checkName :: TlsHandle h g -> String -> Bool
checkName tc n = n `elem` clientNames tc

clientName :: TlsHandle h g -> Maybe String
clientName = listToMaybe . clientNames
