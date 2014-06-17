{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts, PackageImports,
	TupleSections #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module TlsServer (
	CipherSuite(..), KeyExchange(..), BulkEncryption(..),
	ValidateHandle(..), SecretKey,
	run, openClient, checkName, clientName
) where

import Prelude hiding (read)

import Control.Applicative ((<$>), (<*>))
import Control.Monad (unless, liftM)
import "monads-tf" Control.Monad.State (execStateT, get, put, modify)
import "monads-tf" Control.Monad.Error (throwError, catchError)
import Data.Maybe (catMaybes, mapMaybe)
import Data.List (find)
import Data.Word (Word8, Word16)
import Data.HandleLike (HandleLike(..))
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
import HandshakeMonad
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
	maybe (return ()) certificateVerify mpk
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
	msk <- if not dh then return Nothing else generateSecretKey bs >>=
		(>>) <$> serverKeyExchange cr sr ssk bs <*> return . Just
	serverToHelloDone mcs
	mpk <- maybe (return Nothing) ((Just `liftM`) . clientCertificate) mcs
	clientKeyExchange cr cv sr rsk bs msk
	return mpk

clientHello :: (HandleLike h, CPRG g) =>
	HandshakeM h g ([CipherSuite], BS.ByteString, Version)
clientHello = do
	hs <- readHandshake
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
	sr <- randomByteString' 32
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

serverKeyExchange :: (HandleLike h, SecretKey sk, CPRG g,
		Base b, B.Bytable b, B.Bytable (Public b)) =>
	BS.ByteString -> BS.ByteString -> sk -> b -> Secret b -> HandshakeM h g ()
serverKeyExchange cr sr sk ps dhsk = uncurry tlsPut' . contentListToByteString .
	(: []) . ContentHandshake .  HandshakeServerKeyExchange . B.toByteString $
		ServerKeyExchange bs pv
			HashAlgorithmSha1 (signatureAlgorithm sk)
			(sign sk SHA1.hash $ BS.concat [cr, sr, bs, pv])
	where
	bs = B.toByteString ps
	pv = B.toByteString $ calculatePublic ps dhsk

generateSecretKey ::
	(HandleLike h, CPRG g, Base b) => b -> HandshakeM h g (Secret b)
generateSecretKey bs = withRandom' $ generateSecret bs

serverToHelloDone :: (HandleLike h, CPRG g) =>
	Maybe X509.CertificateStore -> HandshakeM h g ()
serverToHelloDone mcs = uncurry tlsPut' . contentListToByteString .
	map ContentHandshake . catMaybes . (: [Just HandshakeServerHelloDone]) $
		mcs >>= return . HandshakeCertificateRequest . CertificateRequest
				clientCertificateTypes
				clientCertificateAlgorithms
			. map (X509.certIssuerDN .
				X509.signedObject . X509.getSigned)
			. X509.listCertificates

clientCertificate :: (ValidateHandle h, CPRG g) =>
	X509.CertificateStore -> HandshakeM h g X509.PubKey
clientCertificate cs = do
	hs <- readHandshake
	(pk, nm) <- case hs of
		HandshakeCertificate cc@(X509.CertificateChain (c : _)) ->
			case X509.certPubKey $ X509.getCertificate c of
				pub -> chk cc >> return (pub, names cc)
		_ -> throwError $ Alert AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"TlsServer.clientCertificate_: not certificate"
	th <- get
	put th { clientNames = nm }
	return pk
	where
	chk cc = do
		rs <- validate' cs cc
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

clientKeyExchange :: (HandleLike h, CPRG g, Base b, B.Bytable (Public b)) =>
	BS.ByteString -> Version -> BS.ByteString -> RSA.PrivateKey ->
	b -> Maybe (Secret b) -> HandshakeM h g ()
clientKeyExchange cr cv sr rsk bs msk = case msk of
	Just sk -> ecClientKeyExchange cr sr bs sk
	_ -> clientKeyExchange_ cr cv sr rsk

ecClientKeyExchange :: (HandleLike h, CPRG g, Base b, B.Bytable (Public b)) =>
	BS.ByteString -> BS.ByteString -> b -> Secret b -> HandshakeM h g ()
ecClientKeyExchange cr sr dhps dhpn = do
	hs <- readHandshake
	case hs of
		HandshakeClientKeyExchange (ClientKeyExchange epms) -> do
			let Right pms = calculateCommon dhps dhpn <$> B.fromByteString epms
			ks <- generateKeys' cr sr pms
			th <- get
			put th { keys = ks }
		_ -> throwError $ Alert AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"TlsServer.clientKeyExchange: not client key exchange"

clientKeyExchange_ :: (HandleLike h, CPRG g) =>
	BS.ByteString -> Version -> BS.ByteString -> RSA.PrivateKey ->
	HandshakeM h g ()
clientKeyExchange_ cr (cvmjr, cvmnr) sr sk = do
	hs <- readHandshake
	case hs of
		HandshakeClientKeyExchange (ClientKeyExchange epms_) -> do
			let epms = BS.drop 2 epms_
			r <- randomByteString' 46
			pms <- mkpms epms `catchError` const (return $ dummy r)
			ks <- generateKeys' cr sr pms
			th <- get
			put th { keys = ks }
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

certificateVerify :: (HandleLike h, CPRG g) => X509.PubKey -> HandshakeM h g ()
certificateVerify (X509.PubKeyRSA pub) = do
	debugCipherSuite' "RSA"
	hash0 <- rsaPadding pub `liftM` handshakeHash'
	hs <- readHandshake
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
certificateVerify (X509.PubKeyECDSA ECDSA.SEC_p256r1 pnt) = do
	debugCipherSuite' "ECDSA"
	hash0 <- handshakeHash'
	hs <- readHandshake
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
certificateVerify p = throwError $ Alert AlertLevelFatal
	AlertDescriptionUnsupportedCertificate
	("TlsServer.certificateVerify: " ++ "not implemented: " ++ show p)

clientChangeCipherSpec :: (HandleLike h, CPRG g) => HandshakeM h g ()
clientChangeCipherSpec = do
	cnt <- readContent
	case cnt of
		ContentChangeCipherSpec ChangeCipherSpec ->
			flushCipherSuite Client `liftM` get >>= put
		_ -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"Not Change Cipher Spec"

clientFinished :: (HandleLike h, CPRG g) => HandshakeM h g ()
clientFinished = do
	fhc <- finishedHash' Client
	cnt <- readContent
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

serverChangeCipherSpec :: (HandleLike h, CPRG g) => HandshakeM h g ()
serverChangeCipherSpec = do
	uncurry tlsPut' . contentToByteString $
		ContentChangeCipherSpec ChangeCipherSpec
	flushCipherSuite Server `liftM` get >>= put

serverFinished :: (HandleLike h, CPRG g) => HandshakeM h g ()
serverFinished = uncurry tlsPut' . contentToByteString .
	ContentHandshake . HandshakeFinished =<< finishedHash' Server

readHandshake :: (HandleLike h, CPRG g) => HandshakeM h g Handshake
readHandshake = do
	cnt <- readContent
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

readContent :: (HandleLike h, CPRG g) => HandshakeM h g Content
readContent = parseContent tlsGet' =<< tlsGetContentType'

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

data ServerKeyExchange
	= ServerKeyExchange BS.ByteString BS.ByteString HashAlgorithm SignatureAlgorithm BS.ByteString
	deriving Show

instance B.Bytable ServerKeyExchange where
	fromByteString = undefined
	toByteString = serverKeyExchangeToByteString

serverKeyExchangeToByteString :: ServerKeyExchange -> BS.ByteString
serverKeyExchangeToByteString
	(ServerKeyExchange params dhYs hashA sigA sn) =
	BS.concat [
		params, dhYs, B.toByteString hashA, B.toByteString sigA,
		B.addLength (undefined :: Word16) sn ]

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

class SecretKey sk where
	sign :: sk -> (BS.ByteString -> BS.ByteString) ->
		BS.ByteString -> BS.ByteString
	signatureAlgorithm :: sk -> SignatureAlgorithm

instance SecretKey ECDSA.PrivateKey where
	sign sk hs bs = let
		Just (ECDSA.Signature r s) = ECDSA.signWith 4649 sk hs bs in
		encodeEcdsaSign $ EcdsaSign 0x30 (2, r) (2, s)
	signatureAlgorithm _ = SignatureAlgorithmEcdsa

instance B.Bytable ECDSA.Curve where
	fromByteString = undefined
	toByteString = encodeCurve

encodeCurve :: ECDSA.Curve -> BS.ByteString
encodeCurve c
	| c == secp256r1 =
		B.toByteString NamedCurve `BS.append` B.toByteString Secp256r1
	| otherwise = error "TlsServer.encodeCurve: not implemented"
