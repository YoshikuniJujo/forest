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
import Control.Arrow (first)
import Control.Monad (unless, liftM)
import "monads-tf" Control.Monad.State (modify)
import "monads-tf" Control.Monad.Error (throwError, catchError)
import "monads-tf" Control.Monad.Error.Class (strMsg)
import Data.Maybe (catMaybes)
import Data.List (find)
import Data.Word (Word8, Word16)
import Data.HandleLike (HandleLike(..))
import "crypto-random" Crypto.Random (CPRG, SystemRNG)

import qualified Data.ByteString as BS
import qualified Data.ASN1.Types as ASN1
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509
import qualified Data.X509.CertificateStore as X509
import qualified Codec.Bytable as B
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Crypto.Types.PubKey.ECC as ECC
import qualified Crypto.Types.PubKey.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.Hash.SHA1 as SHA1

import ReadContent (
	HandshakeM, TlsM, run, execHandshakeM, withRandom, randomByteString,
	TlsHandle,
		setClientNames, checkName, clientName,
		setCipherSuite, flushCipherSuite, debugCipherSuite,
	ValidateHandle(..), validate',
	Alert(..), AlertLevel(..), AlertDescription(..),
	Handshake(..),
		readHandshake, getChangeCipherSpec,
		writeHandshake, writeHandshakeList, putChangeCipherSpec,
	ClientHello(..), ServerHello(..), SessionId(..),
		CipherSuite(..), KeyExchange(..), BulkEncryption(..),
		CompressionMethod(..), HashAlgorithm(..), SignatureAlgorithm(..),
	CertificateRequest(..),
		ClientCertificateType(..), NamedCurve(..), SecretKey(..),
	ClientKeyExchange(..), generateKeys, decryptRsa, rsaPadding,
	DigitallySigned(..), handshakeHash,
	Partner(..), finishedHash)
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

curve :: ECC.Curve
curve = fst (generateBase undefined () :: (ECC.Curve, SystemRNG))

openClient :: (ValidateHandle h, CPRG g, SecretKey sk) =>
	h -> [CipherSuite] ->
	(RSA.PrivateKey, X509.CertificateChain) -> (sk, X509.CertificateChain) ->
	Maybe X509.CertificateStore -> TlsM h g (TlsHandle h g)
openClient h cssv (rsk, rcc) (esk, ecc) mcs = execHandshakeM h $ do
	(cscl, cr, cv) <- clientHello
	(ke, sr) <- serverHello cssv cscl rcc ecc
	mpk <- case ke of
		RSA -> keyExchange False cr cv sr NoDH rsk rsk mcs
		DHE_RSA -> keyExchange True cr cv sr dhparams rsk undefined mcs
		ECDHE_RSA -> keyExchange True cr cv sr curve rsk undefined mcs
		ECDHE_ECDSA -> keyExchange True cr cv sr curve esk undefined mcs
		_ -> throwError "TlsServer.openClient"
	maybe (return ()) certificateVerify mpk
	getChangeCipherSpec >> flushCipherSuite Client
	clientFinished
	putChangeCipherSpec >> flushCipherSuite Server
	writeHandshake . HandshakeFinished =<< finishedHash Server

keyExchange :: (ValidateHandle h, CPRG g, SecretKey sk,
	Base b, B.Bytable b, B.Bytable (Public b)) =>
	Bool -> BS.ByteString -> Version -> BS.ByteString -> b -> sk ->
	RSA.PrivateKey -> Maybe X509.CertificateStore ->
	HandshakeM h g (Maybe X509.PubKey)
keyExchange dh cr cv sr bs ssk rsk mcs = do
	msk <- if not dh
		then return Nothing
		else withRandom (generateSecret bs) >>=
			(>>) <$> serverKeyExchange cr sr ssk bs <*> return . Just
	serverToHelloDone mcs
	mpk <- maybe (return Nothing) ((Just `liftM`) . clientCertificate) mcs
	case msk of
		Just sk -> dhClientKeyExchange cr sr bs sk
		_ -> rsaClientKeyExchange cr cv sr rsk
	return mpk

clientHello :: (HandleLike h, CPRG g) =>
	HandshakeM h g ([CipherSuite], BS.ByteString, Version)
clientHello = do
	hs <- readHandshake
	case hs of
		HandshakeClientHello (ClientHello cv cr _sid cscv cms _) ->
			chk cv cscv cms >> return (cscv, cr, cv)
		_ -> throwError $ Alert AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"TlsServer.clientHello: not client hello"
	where
	chk cv css cms
		| cv < version = throwError $ Alert
			AlertLevelFatal AlertDescriptionProtocolVersion
			"TlsServer.clientHello: client version should 3.3 or more"
		| CipherSuite RSA AES_128_CBC_SHA `notElem` css = throwError $ Alert
			AlertLevelFatal AlertDescriptionIllegalParameter
			"TlsServer.clientHello: no supported cipher suites"
		| compressionMethod `notElem` cms = throwError $ Alert
			AlertLevelFatal AlertDescriptionDecodeError
			"TlsServer.clientHello: no supported compression method"
		| otherwise = return ()

serverHello :: (HandleLike h, CPRG g) => [CipherSuite] -> [CipherSuite] ->
	X509.CertificateChain -> X509.CertificateChain ->
	HandshakeM h g (KeyExchange, BS.ByteString)
serverHello cssv cscl rcc ecc = do
	sr <- randomByteString 32
	cs@(CipherSuite ke _) <- case cipherSuiteSel cssv cscl of
		Just cs -> return cs
		_ -> throwError $ Alert
			AlertLevelFatal AlertDescriptionIllegalParameter
			"TlsServer.serverHello: no supported cipher suites"
	let	cc = case ke of ECDHE_ECDSA -> ecc; _ -> rcc
	writeHandshakeList [
		HandshakeServerHello $ ServerHello version sr sessionId
			cs compressionMethod Nothing,
		HandshakeCertificate cc ]
	modify . first $ setCipherSuite cs
	return (ke, sr)

serverKeyExchange :: (HandleLike h, SecretKey sk, CPRG g,
		Base b, B.Bytable b, B.Bytable (Public b)) =>
	BS.ByteString -> BS.ByteString -> sk -> b -> Secret b -> HandshakeM h g ()
serverKeyExchange cr sr ssk bs sv = writeHandshake .
	HandshakeServerKeyExchange . B.toByteString $
		ServerKeyExchange bs' pv
			HashAlgorithmSha1 (signatureAlgorithm ssk)
			(sign ssk SHA1.hash $ BS.concat [cr, sr, bs', pv])
	where
	bs' = B.toByteString bs
	pv = B.toByteString $ calculatePublic bs sv

data ServerKeyExchange
	= ServerKeyExchange BS.ByteString BS.ByteString
		HashAlgorithm SignatureAlgorithm BS.ByteString deriving Show

instance B.Bytable ServerKeyExchange where
	fromByteString = undefined
	toByteString = serverKeyExchangeToByteString

serverKeyExchangeToByteString :: ServerKeyExchange -> BS.ByteString
serverKeyExchangeToByteString
	(ServerKeyExchange params dhYs hashA sigA sn) =
	BS.concat [
		params, dhYs, B.toByteString hashA, B.toByteString sigA,
		B.addLength (undefined :: Word16) sn ]

data EcCurveType = ExplicitPrime | ExplicitChar2 | NamedCurve | EcCurveTypeRaw Word8
	deriving Show

instance B.Bytable EcCurveType where
	fromByteString = undefined
	toByteString ExplicitPrime = BS.pack [1]
	toByteString ExplicitChar2 = BS.pack [2]
	toByteString NamedCurve = BS.pack [3]
	toByteString (EcCurveTypeRaw w) = BS.pack [w]

instance B.Bytable ECC.Curve where
	fromByteString = undefined
	toByteString = encodeCurve

encodeCurve :: ECC.Curve -> BS.ByteString
encodeCurve c
	| c == secp256r1 =
		B.toByteString NamedCurve `BS.append` B.toByteString Secp256r1
	| otherwise = error "TlsServer.encodeCurve: not implemented"

serverToHelloDone :: (HandleLike h, CPRG g) =>
	Maybe X509.CertificateStore -> HandshakeM h g ()
serverToHelloDone mcs = writeHandshakeList . catMaybes .
	(: [Just HandshakeServerHelloDone]) $
		HandshakeCertificateRequest . CertificateRequest
				clientCertificateTypes
				clientCertificateAlgorithms
			. map (X509.certIssuerDN .
				X509.signedObject . X509.getSigned)
			. X509.listCertificates <$> mcs

clientCertificate :: (ValidateHandle h, CPRG g) =>
	X509.CertificateStore -> HandshakeM h g X509.PubKey
clientCertificate cs = do
	hs <- readHandshake
	case hs of
		HandshakeCertificate cc@(X509.CertificateChain (c : _)) -> do
			chk cc >> setClientNames (names cc)
			return . X509.certPubKey $ X509.getCertificate c
		_ -> throwError $ Alert AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"TlsServer.clientCertificate: not certificate"
	where
	chk cc = do
		rs <- validate' cs cc
		unless (null rs) . throwError $ Alert AlertLevelFatal
			(selectAlert rs)
			("TlsServer.clientCertificate: Validate Failure: "
				++ show rs)
	selectAlert rs
		| X509.Expired `elem` rs = AlertDescriptionCertificateExpired
		| X509.InFuture `elem` rs = AlertDescriptionCertificateExpired
		| X509.UnknownCA `elem` rs = AlertDescriptionUnknownCa
		| otherwise = AlertDescriptionCertificateUnknown
	names cc = maybe id (:) <$> nms <*> ans $ crt cc
	nms = (ASN1.asn1CharacterToString =<<) .
		X509.getDnElement X509.DnCommonName . X509.certSubjectDN
	ans = maybe [] ((\ns -> [s | X509.AltNameDNS s <- ns])
				. \(X509.ExtSubjectAltName ns) -> ns)
			. X509.extensionGet . X509.certExtensions
	crt cc = case cc of
		X509.CertificateChain (t : _) -> X509.getCertificate t
		_ -> error "TlsServer.clientCertificate: empty certificate chain"

dhClientKeyExchange :: (HandleLike h, CPRG g, Base b, B.Bytable (Public b)) =>
	BS.ByteString -> BS.ByteString -> b -> Secret b -> HandshakeM h g ()
dhClientKeyExchange cr sr bs sv = do
	hs <- readHandshake
	case hs of
		HandshakeClientKeyExchange (ClientKeyExchange cke) -> do
			generateKeys cr sr =<< case calculateCommon bs sv <$>
					B.fromByteString cke of
				Left em -> throwError . strMsg $
					"TlsServer.dhClientKeyExchange: " ++ em
				Right p -> return p
		_ -> throwError $ Alert AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"TlsServer.dhClientKeyExchange: not client key exchange"

rsaClientKeyExchange :: (HandleLike h, CPRG g) =>
	BS.ByteString -> Version -> BS.ByteString -> RSA.PrivateKey ->
	HandshakeM h g ()
rsaClientKeyExchange cr (cvmj, cvmn) sr sk = do
	hs <- readHandshake
	case hs of
		HandshakeClientKeyExchange (ClientKeyExchange cke) -> do
			epms <- case B.runBytableM (B.take =<< B.take 2) cke of
				Left em -> throwError . strMsg $
					"TlsServer.clientKeyExchange: " ++ em
				Right (e, "") -> return e
				_ -> throwError "TlsServer.clientKeyExchange"
			generateKeys cr sr =<< mkpms epms `catchError` const
				((BS.cons cvmj . BS.cons cvmn)
					`liftM` randomByteString 46)
		_ -> throwError $ Alert AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"TlsServer.clientKeyExchange: not client key exchange"
	where
	mkpms epms = do
		pms <- decryptRsa sk epms
		unless (BS.length pms == 48) $ throwError "length"
		case BS.unpack $ BS.take 2 pms of
			[pvmj, pvmn] -> unless (pvmj == cvmj && pvmn == cvmn) $
					throwError "version"
			_ -> throwError "never occur"
		return pms

certificateVerify :: (HandleLike h, CPRG g) => X509.PubKey -> HandshakeM h g ()
certificateVerify (X509.PubKeyRSA pub) = do
	debugCipherSuite "RSA"
	hash0 <- rsaPadding pub `liftM` handshakeHash
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
certificateVerify (X509.PubKeyECDSA ECC.SEC_p256r1 pnt) = do
	debugCipherSuite "ECDSA"
	hash0 <- handshakeHash
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
		ECC.Point
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

clientFinished :: (HandleLike h, CPRG g) => HandshakeM h g ()
clientFinished = do
	fhc <- finishedHash Client
	cnt <- readHandshake
	case cnt of
		HandshakeFinished f ->
			unless (f == fhc) . throwError $ Alert
				AlertLevelFatal
				AlertDescriptionDecryptError
				"Finished error"
		_ -> throwError $ Alert
			AlertLevelFatal
			AlertDescriptionUnexpectedMessage
			"Not Finished"
