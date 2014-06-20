{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts, PackageImports,
	TupleSections #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module TlsServer (
	run, openClient, checkName, clientName,
	ValidateHandle(..), SecretKey,
	CipherSuite(..), KeyExchange(..), BulkEncryption(..)
) where

import Prelude hiding (read)

import Control.Applicative ((<$>), (<*>))
import Control.Monad (unless, liftM, ap)
import "monads-tf" Control.Monad.Error (throwError, catchError)
import "monads-tf" Control.Monad.Error.Class (strMsg)
import Data.List (find)
import Data.Word (Word8)
import Data.HandleLike (HandleLike(..))
import "crypto-random" Crypto.Random (CPRG)

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

import HandshakeBase (
	TlsM, run, HandshakeM, execHandshakeM, withRandom, randomByteString,
	TlsHandle, setClientNames, checkName, clientName,
	ValidateHandle(..), validate',
	Alert(..), AlertLevel(..), AlertDescription(..),
	ServerKeyExchange(..), ServerHelloDone(..),
		readHandshake, writeHandshake,
		getChangeCipherSpec, putChangeCipherSpec,
	ClientHello(..), ServerHello(..), SessionId(..),
		CipherSuite(..), KeyExchange(..), BulkEncryption(..),
		CompressionMethod(..), HashAlgorithm(..), SignatureAlgorithm(..),
		setCipherSuite,
	CertificateRequest(..),
		ClientCertificateType(..), SecretKey(..), NamedCurve(..),
	ClientKeyExchange(..),
		generateKeys, decryptRsa, rsaPadding, debugCipherSuite,
	DigitallySigned(..), handshakeHash, flushCipherSuite,
	Partner(..), finishedHash)
import KeyAgreement (Base(..), curve, secp256r1, dhparams)

type Version = (Word8, Word8)

version :: Version
version = (3, 3)

sessionId :: SessionId
sessionId = SessionId ""

mergeCipherSuite :: [CipherSuite] -> [CipherSuite] -> CipherSuite
mergeCipherSuite sv cl = case find (`elem` cl) sv of
	Just cs -> cs; _ -> CipherSuite RSA AES_128_CBC_SHA

compressionMethod :: CompressionMethod
compressionMethod = CompressionMethodNull

clientCertificateTypes :: [ClientCertificateType]
clientCertificateTypes =
	[ClientCertificateTypeRsaSign, ClientCertificateTypeEcdsaSign]

clientCertificateAlgorithms :: [(HashAlgorithm, SignatureAlgorithm)]
clientCertificateAlgorithms = [
	(HashAlgorithmSha256, SignatureAlgorithmRsa),
	(HashAlgorithmSha256, SignatureAlgorithmEcdsa) ]

openClient :: (ValidateHandle h, CPRG g, SecretKey sk) => h -> [CipherSuite] ->
	(RSA.PrivateKey, X509.CertificateChain) -> (sk, X509.CertificateChain) ->
	Maybe X509.CertificateStore -> TlsM h g (TlsHandle h g)
openClient h cssv (rsk, rcc) (esk, ecc) mcs = execHandshakeM h $ do
	(cscl, cr, cv) <- clientHello
	(ke, sr) <- serverHello cssv cscl rcc ecc
	mpk <- case ke of
		RSA -> rsaKeyExchange cr cv sr rsk mcs
		DHE_RSA -> dhKeyExchange cr sr dhparams rsk mcs
		ECDHE_RSA -> dhKeyExchange cr sr curve rsk mcs
		ECDHE_ECDSA -> dhKeyExchange cr sr curve esk mcs
		_ -> throwError "TlsServer.openClient: not implemented"
	maybe (return ()) certificateVerify mpk
	getChangeCipherSpec >> flushCipherSuite Client
	fok <- (==) `liftM` finishedHash Client `ap` readHandshake
	unless fok . throwError $ Alert AlertLevelFatal
		AlertDescriptionDecryptError "TlsServer.openClient: bad Finished"
	putChangeCipherSpec >> flushCipherSuite Server
	writeHandshake =<< finishedHash Server

rsaKeyExchange :: (ValidateHandle h, CPRG g) =>
	BS.ByteString -> Version -> BS.ByteString ->
	RSA.PrivateKey -> Maybe X509.CertificateStore ->
	HandshakeM h g (Maybe X509.PubKey)
rsaKeyExchange cr cv sr rsk mcs = do
	maybe (return ()) certificateRequest mcs
	writeHandshake ServerHelloDone
	mpk <- maybe (return Nothing) (liftM Just . clientCertificate) mcs
	rsaClientKeyExchange cr cv sr rsk
	return mpk

dhKeyExchange :: (ValidateHandle h, CPRG g, SecretKey sk,
	Base b, B.Bytable b, B.Bytable (Public b)) =>
	BS.ByteString -> BS.ByteString -> b -> sk ->
	Maybe X509.CertificateStore -> HandshakeM h g (Maybe X509.PubKey)
dhKeyExchange cr sr bs ssk mcs = do
	sk <- withRandom (generateSecret bs) >>=
		(>>) <$> serverKeyExchange cr sr ssk bs <*> return
	maybe (return ()) certificateRequest mcs
	writeHandshake ServerHelloDone
	mpk <- maybe (return Nothing) (liftM Just . clientCertificate) mcs
	dhClientKeyExchange cr sr bs sk
	return mpk

certificateRequest :: (HandleLike h, CPRG g) =>
	X509.CertificateStore -> HandshakeM h g ()
certificateRequest = writeHandshake . CertificateRequest
		clientCertificateTypes clientCertificateAlgorithms
	. map (X509.certIssuerDN . X509.signedObject . X509.getSigned)
	. X509.listCertificates

clientHello :: (HandleLike h, CPRG g) =>
	HandshakeM h g ([CipherSuite], BS.ByteString, Version)
clientHello = do
	ClientHello cv cr _sid cscv cms _ <- readHandshake
	chk cv cscv cms >> return (cscv, cr, cv)
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
	let	cs@(CipherSuite ke _) = mergeCipherSuite cssv cscl
		cc = case ke of ECDHE_ECDSA -> ecc; _ -> rcc
	sr <- randomByteString 32
	writeHandshake $
		ServerHello version sr sessionId cs compressionMethod Nothing
	writeHandshake cc
	setCipherSuite cs
	return (ke, sr)

serverKeyExchange :: (HandleLike h, SecretKey sk, CPRG g,
		Base b, B.Bytable b, B.Bytable (Public b)) =>
	BS.ByteString -> BS.ByteString -> sk -> b -> Secret b -> HandshakeM h g ()
serverKeyExchange cr sr ssk bs sv = writeHandshake
	. ServerKeyExchange bs' pv HashAlgorithmSha1 (signatureAlgorithm ssk)
	. sign ssk SHA1.hash $ BS.concat [cr, sr, bs', pv]
	where
	bs' = B.toByteString bs
	pv = B.toByteString $ calculatePublic bs sv

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

clientCertificate :: (ValidateHandle h, CPRG g) =>
	X509.CertificateStore -> HandshakeM h g X509.PubKey
clientCertificate cs = do
	cc@(X509.CertificateChain (c : _)) <- readHandshake
	chk cc >> setClientNames (names cc)
	return . X509.certPubKey $ X509.getCertificate c
	where
	chk cc = do
		rs <- validate' cs cc
		unless (null rs) . throwError $ Alert AlertLevelFatal
			(selectAlert rs)
			("TlsServer.clientCertificate: " ++ show rs)
	selectAlert rs
		| X509.UnknownCA `elem` rs = AlertDescriptionUnknownCa
		| X509.Expired `elem` rs = AlertDescriptionCertificateExpired
		| X509.InFuture `elem` rs = AlertDescriptionCertificateExpired
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
	ClientKeyExchange cke <- readHandshake
	generateKeys cr sr =<<
		case calculateCommon bs sv <$> B.fromByteString cke of
			Left em -> throwError . strMsg $
				"TlsServer.dhClientKeyExchange: " ++ em
			Right p -> return p

rsaClientKeyExchange :: (HandleLike h, CPRG g) => BS.ByteString ->
	Version -> BS.ByteString -> RSA.PrivateKey -> HandshakeM h g ()
rsaClientKeyExchange cr (cvj, cvn) sr sk = do
	ClientKeyExchange cke <- readHandshake
	epms <- case B.runBytableM (B.take =<< B.take 2) cke of
		Left em -> throwError . strMsg $
			"TlsServer.clientKeyExchange: " ++ em
		Right (e, "") -> return e
		_ -> throwError "TlsServer.clientKeyExchange: more data"
	generateKeys cr sr =<< mkpms epms `catchError` const
		((BS.cons cvj . BS.cons cvn) `liftM` randomByteString 46)
	where
	mkpms epms = do
		pms <- decryptRsa sk epms
		unless (BS.length pms == 48) $ throwError "length"
		case BS.unpack $ BS.take 2 pms of
			[pvj, pvn] -> unless
				(pvj == cvj && pvn == cvn) $ throwError "version"
			_ -> throwError "never occur"
		return pms

certificateVerify :: (HandleLike h, CPRG g) => X509.PubKey -> HandshakeM h g ()
certificateVerify (X509.PubKeyRSA pub) = do
	debugCipherSuite "RSA"
	hs0 <- rsaPadding pub `liftM` handshakeHash
	DigitallySigned a s <- readHandshake
	case a of
		(HashAlgorithmSha256, SignatureAlgorithmRsa) -> return ()
		_ -> throwError . Alert AlertLevelFatal
			AlertDescriptionDecodeError $
			"TlsServer.certificateVEerify: not implement: " ++ show a
	unless (RSA.ep pub s == hs0) . throwError $ Alert
		AlertLevelFatal AlertDescriptionDecryptError
		"TlsServer.certificateVerify: client auth failed "
certificateVerify (X509.PubKeyECDSA ECC.SEC_p256r1 xy) = do
	debugCipherSuite "ECDSA"
	hs0 <- handshakeHash
	DigitallySigned a s <- readHandshake
	case a of
		(HashAlgorithmSha256, SignatureAlgorithmEcdsa) -> return ()
		_ -> throwError . Alert
			AlertLevelFatal AlertDescriptionDecodeError $
			"TlsServer.certificateverify: not implement: " ++ show a
	unless (ECDSA.verify id (ECDSA.PublicKey secp256r1 $ pnt xy)
		(either error id $ B.fromByteString s) hs0) . throwError $ Alert
			AlertLevelFatal AlertDescriptionDecryptError
			"TlsServer.certificateverify: client auth failed"
	where
	pnt s = let (x, y) = BS.splitAt 32 $ BS.drop 1 s in ECC.Point
		(either error id $ B.fromByteString x)
		(either error id $ B.fromByteString y)
certificateVerify p = throwError . Alert
	AlertLevelFatal AlertDescriptionUnsupportedCertificate $
	"TlsServer.certificateVerify: not implement: " ++ show p
