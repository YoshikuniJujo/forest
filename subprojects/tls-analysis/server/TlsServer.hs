{-# LANGUAGE OverloadedStrings, TypeFamilies, PackageImports, FlexibleContexts #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module TlsServer (
	ValidateHandle(..),
	TlsClient, openClient, withClient, evalClient,
	checkName, getName,
	CipherSuite(..), CipherSuiteKeyEx(..), CipherSuiteMsgEnc(..),

	SecretKey,
) where

import Control.Applicative
import Control.Monad
import Control.Exception
import Data.Maybe
import Data.List
import Data.Word
import Data.HandleLike
import Data.ASN1.Types
import Data.X509
import qualified Data.X509.Validation as X509
import Data.X509.CertificateStore
import System.IO
import Handshake
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

import qualified Crypto.Hash.SHA1 as SHA1

import KeyExchange

import Control.Concurrent.STM

import qualified Codec.Bytable as B

import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding

type Version = (Word8, Word8)

version :: (Word8, Word8)
version = (3, 3)

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

validationCache :: X509.ValidationCache
validationCache = X509.ValidationCache
	(\_ _ _ -> return X509.ValidationCacheUnknown)
	(\_ _ _ -> return ())

validationChecks :: X509.ValidationChecks
validationChecks = X509.defaultChecks { X509.checkFQHN = False }

withClient :: SecretKey sk => Handle -> [CipherSuite] ->
	RSA.PrivateKey -> CertificateChain ->
	(sk, CertificateChain) -> Maybe CertificateStore -> (TlsClient -> IO a) ->
	IO a
withClient h css pk cc ecks mcs =
	bracket (openClientIo h css (pk, cc) ecks mcs) hlClose

openClientIo :: SecretKey sk =>
	Handle -> [CipherSuite] ->
	(RSA.PrivateKey, CertificateChain) -> (sk, CertificateChain) ->
	Maybe CertificateStore -> IO TlsClient
openClientIo h css (pk, cc) ecks mcs = do
	ep <- createEntropyPool
	(tc, ts) <- openClient h css (pk, cc) ecks mcs `runClient`
		(cprgCreate ep :: SystemRNG)
	tstv <- atomically $ newTVar ts
	return $ TlsClient tc tstv

evalClient :: (Monad m, CPRG g) => StateT (TlsClientState g) m a -> g -> m a
evalClient s g = fst `liftM` runClient s g

runClient :: (Monad m, CPRG g) =>
	StateT (TlsClientState g) m a -> g -> m (a, TlsClientState g)
runClient s g = s `runStateT` initialTlsState g

openClient :: (SecretKey sk, ValidateHandle h, CPRG g) => h -> [CipherSuite] ->
	(RSA.PrivateKey, CertificateChain) -> (sk, CertificateChain) ->
	Maybe CertificateStore ->
	HandleMonad (TlsClientConst h g) (TlsClientConst h g)
openClient h css (pk, cc) ecks mcs = runOpenSt h (helloHandshake css pk cc ecks mcs)

curve :: Curve
curve = fst (generateBase undefined () :: (Curve, SystemRNG))

helloHandshake :: (SecretKey sk, CPRG gen, ValidateHandle h) =>
 	[CipherSuite] ->  RSA.PrivateKey -> CertificateChain ->
 	(sk, CertificateChain) -> Maybe CertificateStore -> TlsIo h gen [String]
helloHandshake css sk cc (pkec, ccec) mcs = do
	cv <- hello css cc ccec
	cs <- getCipherSuite
	case cs of
		Just (CipherSuite RSA _) ->
			handshake False NoDH cv sk sk mcs
		Just (CipherSuite DHE_RSA _) ->
			handshake True dhparams cv sk sk mcs
		Just (CipherSuite ECDHE_RSA _) ->
			handshake True curve cv sk sk mcs
		Just (CipherSuite ECDHE_ECDSA _) ->
			handshake True curve cv pkec undefined mcs
		_ -> error "bad"

hello :: (HandleLike h, CPRG gen) => [CipherSuite] ->
	CertificateChain -> CertificateChain -> TlsIo h gen (Word8, Word8)
hello csssv cc ccec = do
	(cv, css) <- clientHello
	serverHello csssv css cc ccec
	return cv

handshake ::
	(Base b, B.Bytable b, SecretKey sk, CPRG gen, ValidateHandle h,
		B.Bytable (Public b)) =>
	Bool -> b -> (Word8, Word8) -> sk ->
	RSA.PrivateKey -> Maybe CertificateStore -> TlsIo h gen [String]
handshake isdh ps cv sks skd mcs = do
	pn <- if not isdh then return $ error "bad" else do
		gen <- getRandomGen
		let (pn, gen') = generateSecret gen ps
		putRandomGen gen'
		return pn
	when isdh $ serverKeyExchange sks ps pn
	serverToHelloDone mcs
	mpn <- maybe (return Nothing) ((Just `liftM`) . clientCertificate) mcs
	dhe <- isEphemeralDH
	if dhe then rcvClientKeyExchange ps pn cv else clientKeyExchange skd cv
	maybe (return ()) (certificateVerify . fst) mpn
	clientChangeCipherSuite
	clientFinished
	serverChangeCipherSuite
	serverFinished
	return $ maybe [] snd mpn

clientHello :: HandleLike h => TlsIo h gen (Version, [CipherSuite])
clientHello = do
	hs <- readHandshake $ \(mj, _) -> mj == 3
	h <- getHandle
	lift . lift . hlDebug h 0 . BSC.pack $ "CLIENT HELLO: " ++ show hs ++ "\n"
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
	sr <- randomByteString 32
	let (vmjr, vmnr) = version in setVersion' (vmjr, vmnr)
	setServerRandom sr
	case cipherSuite' csssv css of
		Just cs -> cacheCipherSuite cs
		_ -> throwError $ Alert
			AlertLevelFatal AlertDescriptionIllegalParameter
			"TlsServer.clientHello: no supported cipher suites"
	mcs <- getCipherSuite
	let	(cs, cccc) = case mcs of
			Just c@(CipherSuite ECDHE_ECDSA _) -> (c, ccec)
			Just c -> (c, cc)
			_ -> error "bad"
		cont = map ContentHandshake $ catMaybes [
			Just . HandshakeServerHello $ ServerHello
				version sr sessionId
				cs compressionMethod Nothing,
			Just $ HandshakeCertificate cccc ]
		(ct, bs) = contentListToByteString cont
	writeByteString ct bs
	updateHash bs

serverKeyExchange ::
	(HandleLike h, Base b, B.Bytable b, B.Bytable (Public b),
		SecretKey sk, CPRG gen) =>
	sk -> b -> Secret b -> TlsIo h gen ()
serverKeyExchange sk ps pn = do
	dh <- isEphemeralDH
	Just rsr <- getServerRandom
	when dh $ sndServerKeyExchange ps pn sk rsr

serverToHelloDone :: (HandleLike h, CPRG gen) =>
	Maybe CertificateStore -> TlsIo h gen ()
serverToHelloDone mcs = do
	let	cont = map ContentHandshake $ catMaybes [
			case mcs of
				Just cs -> Just . HandshakeCertificateRequest
					. CertificateRequest
						[clientCertificateType]
						[clientCertificateAlgorithm]
					. map (certIssuerDN . signedObject . getSigned)
					$ listCertificates cs
				_ -> Nothing,
			Just HandshakeServerHelloDone]
		(ct, bs) = contentListToByteString cont
	writeByteString ct bs
	updateHash bs

class HandleLike h => ValidateHandle h where
	validate :: h -> CertificateStore -> CertificateChain ->
		HandleMonad h [X509.FailedReason]

instance ValidateHandle Handle where
	validate _ cs = X509.validate
		HashSHA256 X509.defaultHooks validationChecks cs validationCache ("", "")

clientCertificate :: ValidateHandle h => CertificateStore -> TlsIo h gen (PubKey, [String])
clientCertificate cs = do
	hs <- readHandshake (== (3, 3))
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
		rs <- lift .lift $ validate h cs cc
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
clientKeyExchange sk (cvmjr, cvmnr) = do
--	h <- getHandle
	hs <- readHandshake (== (3, 3))
	case hs of
		HandshakeClientKeyExchange (EncryptedPreMasterSecret epms_) -> do
			let epms = BS.drop 2 epms_
			r <- randomByteString 46
			pms <- mkpms epms `catchError` const (return $ dummy r)
--			lift . lift . hlDebug h $ "PRE MASTER SECRET: " `BS.append`
--				BSC.pack (show pms) `BS.append` "\n"
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
	h <- getHandle
	getCipherSuite >>= lift . lift . hlDebug h 5 . BSC.pack
		. (++ " - VERIFY WITH RSA\n") . lenSpace 50 . show
	hash0 <- clientVerifyHash pub
	hs <- readHandshake (== (3, 3))
	case hs of
		HandshakeCertificateVerify (DigitallySigned a s) -> do
			chk a
			let hash1 = RSA.ep pub s
			unless (hash1 == hash0) . throwError $ Alert
				AlertLevelFatal
				AlertDescriptionDecryptError -- $
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
	h <- getHandle
	getCipherSuite >>= lift . lift . hlDebug h 5 . BSC.pack
		. (++ " - VERIFY WITH ECDSA\n") . lenSpace 50 . show
	hash0 <- clientVerifyHashEc
--	liftIO . putStrLn $ "CLIENT VERIFY HASH: " ++ show hash0
	hs <- readHandshake (== (3, 3))
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
	("TlsServer.clientCertificate: " ++ "not implemented: " ++ show p)

lenSpace :: Int -> String -> String
lenSpace n str = str ++ replicate (n - length str) ' '

clientChangeCipherSuite :: HandleLike h => TlsIo h gen ()
clientChangeCipherSuite = do
	cnt <- readContent (== (3, 3))
	case cnt of
		ContentChangeCipherSpec ChangeCipherSpec ->
			flushCipherSuite Client
		_ -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"Not Change Cipher Spec"

clientFinished :: HandleLike h => TlsIo h gen ()
clientFinished = do
	fhc <- finishedHash Client
--	liftIO . putStrLn $ "FINISHED HASH: " ++ show fhc
	cnt <- readContent (== (3, 3))
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

serverChangeCipherSuite :: (HandleLike h, CPRG gen) => TlsIo h gen ()
serverChangeCipherSuite = do
	uncurry writeByteString . contentToByteString $
		ContentChangeCipherSpec ChangeCipherSpec
	flushCipherSuite Server

serverFinished :: (HandleLike h, CPRG gen) => TlsIo h gen ()
serverFinished = uncurry writeByteString . contentToByteString .
	ContentHandshake . HandshakeFinished =<< finishedHash Server

readHandshake :: HandleLike h => ((Word8, Word8) -> Bool) -> TlsIo h gen Handshake
readHandshake ck = do
	cnt <- readContent ck
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

readContent :: HandleLike h => ((Word8, Word8) -> Bool) -> TlsIo h gen Content
readContent vc = do
	c <- const `liftM` getContent (readBufContentType vc) (readByteString (== (3, 3)))
		`ap` updateSequenceNumber Client
	case contentToByteString c of
		(ContentTypeHandshake, bs) -> updateHash bs
		_ -> return ()
	return c
	
sndServerKeyExchange ::
	(HandleLike h, SecretKey sk, CPRG gen,
	Base b, B.Bytable b, B.Bytable (Public b)) =>
	b -> Secret b -> sk -> BS.ByteString -> TlsIo h gen ()
sndServerKeyExchange ps dhsk pk sr = do
	Just cr <- getClientRandom
	let	ske = HandshakeServerKeyExchange . serverKeyExchangeToByteString .
			addSign pk cr sr $
			ServerKeyExchange
				(B.toByteString ps)
				(B.toByteString $ calculatePublic ps dhsk)
				HashAlgorithmSha1 (signatureAlgorithm pk) "hogeru"
		cont = [ContentHandshake ske]
		(ct, bs) = contentListToByteString cont
	writeByteString ct bs
	updateHash bs

rcvClientKeyExchange :: (HandleLike h, Base b, B.Bytable (Public b)) =>
	b -> Secret b -> Version -> TlsIo h gen ()
rcvClientKeyExchange dhps dhpn (_cvmjr, _cvmnr) = do
	hs <- readHandshake (== (3, 3))
	case hs of
		HandshakeClientKeyExchange (EncryptedPreMasterSecret epms) -> do
--			liftIO . putStrLn $ "CLIENT KEY: " ++ show epms
			let Right pms = calculateCommon dhps dhpn <$> B.fromByteString epms
--			liftIO . putStrLn $ "PRE MASTER SECRET: " ++ show pms
			generateKeys pms
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
parseContent rd ContentTypeHandshake = ContentHandshake `liftM` takeHandshake rd
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
	(ContentTypeHandshake, handshakeToByteString hss)

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

instance B.Bytable Curve where
	fromByteString = undefined
	toByteString = encodeCurve

encodeCurve :: Curve -> BS.ByteString
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
decodeSignature bs = case decodeASN1' DER bs of
	Right [Start Sequence, IntVal r, IntVal s, End Sequence] ->
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
		a = [Start Sequence, Start Sequence, OID [1, 3, 14, 3, 2, 26],
			Null, End Sequence, OctetString h, End Sequence]
		b = encodeASN1' DER a
		pd = BS.concat [
			"\x00\x01", BS.replicate (125 - BS.length b) 0xff,
			"\NUL", b ] in
		RSA.dp Nothing sk pd
	signatureAlgorithm _ = SignatureAlgorithmRsa
