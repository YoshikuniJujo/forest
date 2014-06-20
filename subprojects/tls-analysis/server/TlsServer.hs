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
import Numeric (readHex)
import "crypto-random" Crypto.Random (CPRG)

import qualified Data.ByteString as BS
import qualified Data.ASN1.Types as ASN1
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509
import qualified Data.X509.CertificateStore as X509
import qualified Codec.Bytable as B
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA
import qualified Crypto.Types.PubKey.DH as DH
import qualified Crypto.Types.PubKey.ECC as ECC
import qualified Crypto.Types.PubKey.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.Hash.SHA1 as SHA1

import HandshakeBase (
	TlsM, run, HandshakeM, execHandshakeM, withRandom, randomByteString,
	TlsHandle, setClientNames, checkName, clientName,
		readHandshake, writeHandshake,
		getChangeCipherSpec, putChangeCipherSpec,
	ValidateHandle(..), validate',
	Alert(..), AlertLevel(..), AlertDescription(..),
	ServerKeyExchange(..), ServerHelloDone(..),
	ClientHello(..), ServerHello(..), SessionId(..),
		CipherSuite(..), KeyExchange(..), BulkEncryption(..),
		CompressionMethod(..), HashAlgorithm(..), SignatureAlgorithm(..),
		setCipherSuite,
	CertificateRequest(..),
		ClientCertificateType(..), SecretKey(..),
	ClientKeyExchange(..),
		generateKeys, decryptRsa, rsaPadding, debugCipherSuite,
	DigitallySigned(..), handshakeHash, flushCipherSuite,
	Partner(..), finishedHash)
import KeyAgreement (DhParam(..))

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

secp256r1 :: ECC.Curve
secp256r1 = ECC.getCurveByName ECC.SEC_p256r1

dhparams3072 :: DH.Params
dhparams3072 = DH.Params p 2
	where [(p, "")] = readHex $
		"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd1" ++
		"29024e088a67cc74020bbea63b139b22514a08798e3404dd" ++
		"ef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245" ++
		"e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed" ++
		"ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3d" ++
		"c2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f" ++
		"83655d23dca3ad961c62f356208552bb9ed529077096966d" ++
		"670c354e4abc9804f1746c08ca18217c32905e462e36ce3b" ++
		"e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9" ++
		"de2bcbf6955817183995497cea956ae515d2261898fa0510" ++
		"15728e5a8aaac42dad33170d04507a33a85521abdf1cba64" ++
		"ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7" ++
		"abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6b" ++
		"f12ffa06d98a0864d87602733ec86a64521f2b18177b200c" ++
		"bbe117577a615d6c770988c0bad946e208e24fa074e5ab31" ++
		"43db5bfce0fd108e4b82d120a93ad2caffffffffffffffff"

openClient :: (ValidateHandle h, CPRG g, SecretKey sk) => h -> [CipherSuite] ->
	(RSA.PrivateKey, X509.CertificateChain) -> (sk, X509.CertificateChain) ->
	Maybe X509.CertificateStore -> TlsM h g (TlsHandle h g)
openClient h cssv (rsk, rcc) (esk, ecc) mcs = execHandshakeM h $ do
	(cscl, cr, cv) <- clientHello
	(ke, sr) <- serverHello cssv cscl rcc ecc
	mpk <- case ke of
		RSA -> rsaKeyExchange cr cv sr rsk mcs
		DHE_RSA -> dhKeyExchange cr sr dhparams3072 rsk mcs
		ECDHE_RSA -> dhKeyExchange cr sr secp256r1 rsk mcs
		ECDHE_ECDSA -> dhKeyExchange cr sr secp256r1 esk mcs
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
rsaKeyExchange cr cv sr rsk mcs = return const
	`ap` requestToCertificate mcs
	`ap` rsaClientKeyExchange cr cv sr rsk

dhKeyExchange :: (ValidateHandle h, CPRG g, SecretKey sk,
	DhParam b, B.Bytable b, B.Bytable (Public b)) =>
	BS.ByteString -> BS.ByteString -> b -> sk ->
	Maybe X509.CertificateStore -> HandshakeM h g (Maybe X509.PubKey)
dhKeyExchange cr sr bs ssk mcs = do
	sk <- withRandom $ generateSecret bs
	serverKeyExchange cr sr ssk bs sk
	return const
		`ap` requestToCertificate mcs
		`ap` dhClientKeyExchange cr sr bs sk

requestToCertificate :: (ValidateHandle h, CPRG g) =>
	Maybe X509.CertificateStore -> HandshakeM h g (Maybe X509.PubKey)
requestToCertificate mcs = do
	maybe (return ()) certificateRequest mcs
	writeHandshake ServerHelloDone
	maybe (return Nothing) (liftM Just . clientCertificate) mcs

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
		DhParam b, B.Bytable b, B.Bytable (Public b)) =>
	BS.ByteString -> BS.ByteString -> sk -> b -> Secret b -> HandshakeM h g ()
serverKeyExchange cr sr ssk bs sv = writeHandshake
	. ServerKeyExchange bs' pv HashAlgorithmSha1 (signatureAlgorithm ssk)
	. sign ssk (SHA1.hash, 64) $ BS.concat [cr, sr, bs', pv]
	where
	bs' = B.toByteString bs
	pv = B.toByteString $ calculatePublic bs sv

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

dhClientKeyExchange :: (HandleLike h, CPRG g, DhParam b, B.Bytable (Public b)) =>
	BS.ByteString -> BS.ByteString -> b -> Secret b -> HandshakeM h g ()
dhClientKeyExchange cr sr bs sv = do
	ClientKeyExchange cke <- readHandshake
	generateKeys cr sr =<<
		case calculateShared bs sv <$> B.fromByteString cke of
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
