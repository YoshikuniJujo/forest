{-# LANGUAGE OverloadedStrings, TypeFamilies, TupleSections, FlexibleContexts,
	PackageImports #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module TlsServer (
	run, openClient, checkName, clientName,
	ValidateHandle(..), CertSecretKey,
	CipherSuite(..), KeyExchange(..), BulkEncryption(..)) where

import Control.Applicative ((<$>), (<*>))
import Control.Monad (unless, liftM, ap)
import "monads-tf" Control.Monad.Error (catchError)
import qualified "monads-tf" Control.Monad.Error as E (throwError)
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

import HandshakeBase ( -- debug,
	TlsM, run, HandshakeM, execHandshakeM, withRandom, randomByteString,
	TlsHandle, setClientNames, checkName, clientName,
		readHandshake, getChangeCipherSpec,
		writeHandshake, putChangeCipherSpec,
	ValidateHandle(..), handshakeValidate,
	AlertLevel(..), AlertDesc(..),
	ServerKeyExchange(..), ServerHelloDone(..),
	ClientHello(..), ServerHello(..), SessionId(..),
		CipherSuite(..), KeyExchange(..), BulkEncryption(..),
		CompressionMethod(..), HashAlg(..), SignAlg(..),
		setCipherSuite,
	certificateRequest, ClientCertificateType(..), SecretKey(..),
	ClientKeyExchange(..), Epms(..),
		generateKeys, decryptRsa, rsaPadding, debugCipherSuite,
	DigitallySigned(..), handshakeHash, flushCipherSuite,
	Side(..), RW(..), finishedHash,
	DhParam(..), dh3072Modp, secp256r1, throwError,
	CertSecretKey(..) )

type Version = (Word8, Word8)

version :: Version
version = (3, 3)

filterCS :: [(CertSecretKey, X509.CertificateChain)] ->
	[CipherSuite] -> [CipherSuite]
filterCS crts cs = case find isEcdsa crts of
	Just _ -> cs
	_ -> filter (not . isEcdsaCS) cs

isEcdsa :: (CertSecretKey, X509.CertificateChain) -> Bool
isEcdsa (EcdsaKey _, _) = True
isEcdsa _ = False

isRsa :: (CertSecretKey, X509.CertificateChain) -> Bool
isRsa (RsaKey _, _) = True
isRsa _ = False

isEcdsaCS :: CipherSuite -> Bool
isEcdsaCS (CipherSuite ECDHE_ECDSA _) = True
isEcdsaCS _ = False

openClient :: (ValidateHandle h, CPRG g) => h ->
	[CipherSuite] ->
	[(CertSecretKey, X509.CertificateChain)] ->
	Maybe X509.CertificateStore -> TlsM h g (TlsHandle h g)
openClient h cssv crts mcs = execHandshakeM h $ do
	(cs@(CipherSuite ke be), cr, cv) <- clientHello $ filterCS crts cssv
	sr <- serverHello cs rcc ecc
	setCipherSuite cs
	ha <- case be of
		AES_128_CBC_SHA -> return Sha1
		AES_128_CBC_SHA256 -> return Sha256
		_ -> E.throwError
			"TlsServer.openClient: not implemented bulk encryption type"
	mpk <- (\kep -> kep (cr, sr) mcs) $ case ke of
		RSA -> rsaKeyExchange rsk cv
		DHE_RSA -> dhKeyExchange ha dh3072Modp rsk
		ECDHE_RSA -> dhKeyExchange ha secp256r1 rsk
		ECDHE_ECDSA -> dhKeyExchange ha secp256r1 esk
		_ -> \_ _ -> E.throwError
			"TlsServer.openClient: not implemented key exchange type"
	maybe (return ()) certificateVerify mpk
	getChangeCipherSpec >> flushCipherSuite Read
	fok <- (==) `liftM` finishedHash Client `ap` readHandshake
	unless fok $ throwError ALFatal ADDecryptError
		"TlsServer.openClient: wrong finished hash"
	putChangeCipherSpec >> flushCipherSuite Write
	writeHandshake =<< finishedHash Server
	where
	Just (RsaKey rsk, rcc) = find isRsa crts
	Just (EcdsaKey esk, ecc) = find isEcdsa crts

rsaKeyExchange :: (ValidateHandle h, CPRG g) => RSA.PrivateKey -> Version ->
	(BS.ByteString, BS.ByteString) -> Maybe X509.CertificateStore ->
	HandshakeM h g (Maybe X509.PubKey)
rsaKeyExchange rsk cv rs mcs = return const
	`ap` requestAndCertificate mcs
	`ap` rsaClientKeyExchange rsk cv rs

dhKeyExchange :: (ValidateHandle h, CPRG g, SecretKey sk, Show (Secret dp),
		Show (Public dp),
		DhParam dp, B.Bytable dp, B.Bytable (Public dp)) =>
	HashAlg -> dp -> sk ->
	(BS.ByteString, BS.ByteString) -> Maybe X509.CertificateStore ->
	HandshakeM h g (Maybe X509.PubKey)
dhKeyExchange ha dp ssk rs mcs = do
	sv <- withRandom $ generateSecret dp
	serverKeyExchange ha dp sv ssk rs
	return const
		`ap` requestAndCertificate mcs
		`ap` dhClientKeyExchange dp sv rs

clientHello :: (HandleLike h, CPRG g) =>
	[CipherSuite] -> HandshakeM h g (CipherSuite, BS.ByteString, Version)
clientHello cssv = do
	ClientHello cv cr _sid cscl cms _ <- readHandshake
	chk cv cscl cms >> return (merge cssv cscl, cr, cv)
	where
	merge sv cl = case find (`elem` cl) sv of
		Just cs -> cs; _ -> CipherSuite RSA AES_128_CBC_SHA
	chk cv css cms
		| cv < version = throwError ALFatal ADProtocolVersion $
			pmsg ++ "client version should 3.3 or more"
		| CipherSuite RSA AES_128_CBC_SHA `notElem` css =
			throwError ALFatal ADIllegalParameter $
				pmsg ++ "TLS_RSA_AES_128_CBC_SHA must be supported"
		| CompressionMethodNull `notElem` cms =
			throwError ALFatal ADDecodeError $
				pmsg ++ "compression method NULL must be supported"
		| otherwise = return ()
		where pmsg = "TlsServer.clientHello: "

serverHello :: (HandleLike h, CPRG g) => CipherSuite ->
	X509.CertificateChain -> X509.CertificateChain ->
	HandshakeM h g BS.ByteString
serverHello cs@(CipherSuite ke _) rcc ecc = do
	sr <- randomByteString 32
	writeHandshake $ ServerHello
		version sr (SessionId "") cs CompressionMethodNull Nothing
	writeHandshake $ case ke of ECDHE_ECDSA -> ecc; _ -> rcc
	return sr
serverHello _ _ _ = E.throwError "TlsServer.serverHello: never occur"

serverKeyExchange :: (HandleLike h, CPRG g, SecretKey sk,
		DhParam dp, B.Bytable dp, B.Bytable (Public dp)) =>
	HashAlg -> dp -> Secret dp -> sk ->
	(BS.ByteString, BS.ByteString) -> HandshakeM h g ()
serverKeyExchange ha dp sv ssk (cr, sr) = do
	bl <- withRandom $ generateBlinder ssk
	writeHandshake
		. ServerKeyEx edp pv ha (signatureAlgorithm ssk)
		. sign ha bl ssk $ BS.concat [cr, sr, edp, pv]
	where
	edp = B.encode dp
	pv = B.encode $ calculatePublic dp sv

requestAndCertificate :: (ValidateHandle h, CPRG g) =>
	Maybe X509.CertificateStore -> HandshakeM h g (Maybe X509.PubKey)
requestAndCertificate mcs = do
	flip (maybe $ return ()) mcs $ writeHandshake . certificateRequest
		[CTRsaSign, CTEcdsaSign] [(Sha256, Rsa), (Sha256, Ecdsa)]
	writeHandshake ServerHelloDone
	maybe (return Nothing) (liftM Just . clientCertificate) mcs

clientCertificate :: (ValidateHandle h, CPRG g) =>
	X509.CertificateStore -> HandshakeM h g X509.PubKey
clientCertificate cs = do
	cc@(X509.CertificateChain (c : _)) <- readHandshake
	chk cc >> setClientNames (names cc)
	return . X509.certPubKey $ X509.getCertificate c
	where
	chk cc = do
		rs <- handshakeValidate cs cc
		unless (null rs) . throwError ALFatal (selectAlert rs) $
			"TlsServer.clientCertificate: " ++ show rs
	selectAlert rs
		| X509.UnknownCA `elem` rs = ADUnknownCa
		| X509.Expired `elem` rs = ADCertificateExpired
		| X509.InFuture `elem` rs = ADCertificateExpired
		| otherwise = ADCertificateUnknown
	names cc = maybe id (:) <$> nms <*> ans $ crt cc
	nms = (ASN1.asn1CharacterToString =<<) .
		X509.getDnElement X509.DnCommonName . X509.certSubjectDN
	ans = maybe [] ((\ns -> [s | X509.AltNameDNS s <- ns])
				. \(X509.ExtSubjectAltName ns) -> ns)
			. X509.extensionGet . X509.certExtensions
	crt cc = case cc of
		X509.CertificateChain (t : _) -> X509.getCertificate t
		_ -> error "TlsServer.clientCertificate: empty certificate chain"

rsaClientKeyExchange :: (HandleLike h, CPRG g) => RSA.PrivateKey ->
	Version -> (BS.ByteString, BS.ByteString) -> HandshakeM h g ()
rsaClientKeyExchange sk (cvj, cvn) rs = do
	Epms epms <- readHandshake
	generateKeys Server rs =<< mkpms epms `catchError` const
		((BS.cons cvj . BS.cons cvn) `liftM` randomByteString 46)
	where
	mkpms epms = do
		pms <- decryptRsa sk epms
		unless (BS.length pms == 48) $ E.throwError "mkpms: length"
		case BS.unpack $ BS.take 2 pms of
			[pvj, pvn] -> unless (pvj == cvj && pvn == cvn) $
				E.throwError "mkpms: version"
			_ -> E.throwError "mkpms: never occur"
		return pms

dhClientKeyExchange :: (HandleLike h, CPRG g, DhParam dp, B.Bytable (Public dp),
	Show (Public dp)) =>
	dp -> Secret dp -> (BS.ByteString, BS.ByteString) -> HandshakeM h g ()
dhClientKeyExchange dp sv rs = do
	ClientKeyExchange cke <- readHandshake
	let Right pv = B.decode cke
	generateKeys Server rs =<< case Right $ calculateShared dp sv pv of
		Left em -> E.throwError . strMsg $
			"TlsServer.dhClientKeyExchange: " ++ em
		Right sh -> return sh

certificateVerify :: (HandleLike h, CPRG g) => X509.PubKey -> HandshakeM h g ()
certificateVerify (X509.PubKeyRSA pk) = do
	debugCipherSuite "RSA"
	hs0 <- rsaPadding pk `liftM` handshakeHash
	DigitallySigned a s <- readHandshake
	case a of
		(Sha256, Rsa) -> return ()
		_ -> throwError ALFatal ADDecodeError $
			"TlsServer.certificateVEerify: not implement: " ++ show a
	unless (RSA.ep pk s == hs0) $ throwError ALFatal ADDecryptError
		"TlsServer.certificateVerify: client auth failed "
certificateVerify (X509.PubKeyECDSA ECC.SEC_p256r1 xy) = do
	debugCipherSuite "ECDSA"
	hs0 <- handshakeHash
	DigitallySigned a s <- readHandshake
	case a of
		(Sha256, Ecdsa) -> return ()
		_ -> throwError ALFatal ADDecodeError $
			"TlsServer.certificateverify: not implement: " ++ show a
	unless (ECDSA.verify id
		(ECDSA.PublicKey secp256r1 $ pnt xy)
		(either error id $ B.decode s) hs0) $ throwError
			ALFatal ADDecryptError
			"TlsServer.certificateverify: client auth failed"
	where
	pnt s = let (x, y) = BS.splitAt 32 $ BS.drop 1 s in ECC.Point
		(either error id $ B.decode x)
		(either error id $ B.decode y)
certificateVerify p = throwError ALFatal ADUnsupportedCertificate $
	"TlsServer.certificateVerify: not implement: " ++ show p
