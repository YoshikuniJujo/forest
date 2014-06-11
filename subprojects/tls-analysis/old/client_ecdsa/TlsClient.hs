{-# LANGUAGE OverloadedStrings, ScopedTypeVariables #-}

module TlsClient (
	TlsServer,
	openTlsServer, tPut, tGetByte, tGetLine, tGet, tGetContent, tClose,

	tPutWithCT,
	Content(..),
	ContentType(..),
	Handshake(..),
	Version(..),

	CipherSuite(..), CipherSuiteKeyEx(..), CipherSuiteMsgEnc(..),
) where

import System.IO
import Control.Applicative
import Control.Monad
import qualified Data.ByteString as BS
import Data.X509
import Data.X509.CertificateStore
import Data.X509.Validation
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA

import Numeric

import Fragment
import Content
import Basic

import Crypto.PubKey.ECC.Prim
import Crypto.Types.PubKey.ECC

openTlsServer :: [CipherSuite] ->
	[(RSA.PrivateKey, CertificateChain)] -> CertificateStore -> Handle ->
	IO TlsServer
openTlsServer css ccs certStore sv = runOpen (handshake css ccs certStore) sv

isIncluded :: (RSA.PrivateKey, CertificateChain) -> [DistinguishedName] -> Bool
isIncluded (_, CertificateChain certs) dns = let
	idn = certIssuerDN . signedObject . getSigned $ last certs in
	idn `elem` dns

handshake :: [CipherSuite] ->
	[(RSA.PrivateKey, CertificateChain)] -> CertificateStore ->
	TlsIo Content ()
handshake css ccs certStore = do

	-------------------------------------------
	--     CLIENT HELLO                      --
	-------------------------------------------
	cr <- Random <$> randomByteString 32
	let ch = clientHello cr (3, 3) (3, 3) css
	{-
		[	CipherSuite ECDHE_ECDSA AES_128_CBC_SHA,
			CipherSuite ECDHE_ECDSA AES_128_CBC_SHA256,
			CipherSuite ECDHE_RSA AES_128_CBC_SHA,
			CipherSuite ECDHE_RSA AES_128_CBC_SHA256]
			-}
		[CompressionMethodNull]
		(Just [	ExtensionEllipticCurve [Secp256r1],
			ExtensionEcPointFormat [EcPointFormatUncompressed] ])
	writeContent ch
	fragmentUpdateHash $ contentToFragment ch
	maybe (throwError "No Client Hello") setClientRandom $ clientRandom ch

	-------------------------------------------
	--     SERVER HELLO                      --
	-------------------------------------------
	sh <- readContent
	liftIO $ print sh
	maybe (throwError "No Server Hello") setVersion $ serverVersion sh
	maybe (throwError "No Server Hello") setServerRandom $
		serverRandom sh
	maybe (throwError "No Server Hello") cacheCipherSuite $
		serverCipherSuite sh
	liftIO . putStrLn $ "SERVER HELLO: " ++ take 60 (show sh) ++ "..."

	-------------------------------------------
	--     SERVER CERTIFICATE                --
	-------------------------------------------
	crt <- readContent
	let	Just scc@(CertificateChain (cert : _)) = certificateChain crt
		PubKeyECDSA cn pub = certPubKey $ getCertificate cert
	case cn of
		SEC_p256r1 -> return ()
		_ -> throwError "NOW, only SEC_p256r1"
	liftIO . putStrLn $
		"KEY: curve name = " ++ show cn ++ " pub key = " ++ show pub
	let	(bspubx, bspuby) = BS.splitAt 32 $ BS.tail pub
		[pubx, puby] = map byteStringToInteger [bspubx, bspuby]
	liftIO . putStrLn $
		"X = " ++ show pubx
	liftIO . putStrLn $
		"Y = " ++ show puby
	v <- liftIO $ validateDefault certStore
		(ValidationCache query add) ("localhost", "localhost da") scc
	liftIO . putStrLn $ "VALIDATE RESULT: " ++ show v
	unless (null v) $ throwError "SERVER VALIDATION FAILURE"
	liftIO . putStrLn $ "CERTIFICATE: " ++ take 60 (show crt) ++ "..."
	liftIO . putStrLn $ "CERTIFICATE Chain: " ++ take 60 (show scc) ++ "..."
--	liftIO . putStrLn $ "PUBKEY: " ++ take 60 (show pub) ++ "..."

	-------------------------------------------
	--     CERTIFICATE REQUEST               --
	-------------------------------------------
	-------------------------------------------
	--     SERVER HELLO DONE                 --
	-------------------------------------------
--	(crtReq, epms, pms) <- serverHelloDone (error "no pub key") -- pub
	(crtReq, epms, pms) <- serverHelloDone $
		ECDSA.PublicKey secp256r1 (Point pubx puby)

	liftIO . putStrLn $ "PMS: " ++ show pms

	let	Just (CertificateRequest _ _ sdn) = crtReq
		(pk, cc) = case filter (`isIncluded` sdn) ccs of
			(p, c) : _ -> (p, c)
			_ -> error "bad"

	-------------------------------------------
	--     CLIENT CERTIFICATE                --
	-------------------------------------------
	case crtReq of
		Just _ -> do
			writeContent $ certificate cc
			fragmentUpdateHash . contentToFragment $ certificate cc
		_ -> return ()

	-------------------------------------------
	--     CLIENT KEY EXCHANGE               --
	-------------------------------------------
--	let pmsVer = if OptPmsVerErr `elem` opts then "\x99\x99" else "\x03\x03"
--	pms <- (pmsVer `BS.append`) <$> randomByteString 46
--	epms' <- encryptRSA pub pms
--	liftIO $ putStrLn $ "Encrypted Pre Master Secret: " ++ show epms'
	generateKeys pms
--	let	cke'' = makeClientKeyExchange $ EncryptedPreMasterSecret epms'
	let	cke'' = makeClientKeyExchange $ EncryptedPreMasterSecret epms
	writeContent cke''
	liftIO . putStrLn $ "CLIENT KEY EXCHANGE: " ++ show (contentToFragment cke'')
	liftIO . putStrLn $ "CLIENT KEY EXCHANGE: " ++ show cke''
	fragmentUpdateHash $ contentToFragment cke''
--	liftIO $ putStrLn $ "KEY EXCHANGE: " ++ show (contentToFragment cke'')
	liftIO $ putStrLn "GENERATE KEYS"

--	debugPrintKeys

	-------------------------------------------
	--     CERTIFICATE VERIFY                --
	-------------------------------------------
	case crtReq of
		Just _ -> do
			signed <- clientVerifySign pk False
			let	(ha, sa) = (HashAlgorithmSha256,
					SignatureAlgorithmRsa)
				cv = makeVerify ha sa signed
			writeContent cv
			fragmentUpdateHash . contentToFragment $ cv
		_ -> return ()

	-------------------------------------------
	--     CLIENT CHANGE CIPHER SPEC         --
	-------------------------------------------
	writeContent changeCipherSpec
	fragmentUpdateHash $ contentToFragment changeCipherSpec
	flushCipherSuite Client

	-------------------------------------------
	--     CLIENT FINISHED                   --
	-------------------------------------------
	fhc <- finishedHash Client
	liftIO . putStrLn $ "CLIENT FINISHED: " ++ show fhc
	writeContent $ finished fhc
	fragmentUpdateHash . contentToFragment $ finished fhc

	liftIO $ putStrLn "CLIENT FINISHED DONE"

	-------------------------------------------
	--     SERVER CHANGE CIPHER SPEC         --
	-------------------------------------------
	sccs <- readContent
	when (doesChangeCipherSpec sccs) $ flushCipherSuite Server
	liftIO $ print sccs
	when (isFatal sccs) . error $ show sccs
	liftIO . putStrLn $ "SERVER CHANGE CIPHER SPEC: " ++ take 60 (show sccs)

	-------------------------------------------
	--     SERVER FINISHED                   --
	-------------------------------------------
	sfhc <- finishedHash Server
	scf <- readContent
	updateSequenceNumberSmart Server
	sfinish <- maybe (throwError $ "Not Finished: " ++ show scf)
		return $ getFinish scf
	liftIO $ do
		putStrLn $ "SERVER FINISHED FIREFOX     : " ++ take 60 (show sfinish)
		putStrLn $ "SERVER FINISHED CALCULATE   : " ++ take 60 (show sfhc)

private :: Integer
private = 500

serverHelloDone :: ECDSA.PublicKey -> TlsIo Content (Maybe CertificateRequest, BS.ByteString, BS.ByteString)
serverHelloDone pub = do

	-------------------------------------------
	--     CERTIFICATE REQUEST               --
	-------------------------------------------
	cske <- readContent
	liftIO . putStrLn $
--		"CERTIFICATE REQUEST: " ++ take 60 (show crtReq) ++ "..."
		"CERTIFICATE REQUEST: " ++ show cske

	let	ContentHandshake _ (HandshakeServerKeyExchange ske) = cske
		ServerKeyExchangeEc _ct nc _t p _ _ _ _ = ske

	cr <- getClientRandom
	sr <- getServerRandom
	liftIO . print $ verifyServerKeyExchange pub cr sr ske
	liftIO . putStrLn $ "\nSERVER KEY EXCHANGE: " ++ show ske ++ "\n"

--	let field = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff

	liftIO . putStrLn $ "NAMED CURVE: " ++ show nc
	liftIO . putStrLn $ "(x, y) = " ++ show p
	liftIO . putStrLn $ "x = 0x" ++ showHex ((\(Point x _) -> x) p) ""
	liftIO . putStrLn $ "y = 0x" ++ showHex ((\(Point _ y) -> y) p) ""

	let	public = pointMul secp256r1 private (ecc_g $ common_curve secp256r1)
		epms = encodePoint 4 public
--		pms = encodePoint 4 $ pointMul secp256r1 private p
		pms = let Point x _ = pointMul secp256r1 private p in integerToByteString x

	liftIO . putStrLn $ "PUBLIC: " ++ show public
	liftIO . putStrLn $ "EPMS  : " ++ concatMap (`showHex` "") (BS.unpack epms)

--	g <- getRandomGen
--	let	(pr, g') = generatePrivate g ps
--		dhsk = getShared ps pr ys
--	setRandomGen g'
--	liftIO . putStrLn $ "PRIVATE NUMBER: " ++ show pr
--	liftIO . putStrLn $ "SHARED KEY    : " ++ show dhsk

	crtReq <- readContent

	liftIO . putStrLn $ "CRT REQ or SHD: " ++ show crtReq

	unless (doesServerHelloDone crtReq) $ do

	-------------------------------------------
	--     SERVER HELLO DONE                 --
	-------------------------------------------
		shd <- readContent
		liftIO . putStrLn $ "SERVER HELLO DONE: " ++ take 60 (show shd) ++ "..."

	return (getCertificateRequest crtReq, epms, pms)

readContent :: TlsIo Content Content
readContent = do
	c <- readCached readContentList
	fragmentUpdateHash $ contentToFragment c
	return c

readContentList :: TlsIo Content [Content]
readContentList = (\ec -> case ec of
		Right c -> c;
		Left err -> error $ "readContentList: " ++ err) .
	fragmentToContent <$> readFragment

_writeContentList :: Partner -> [Content] -> TlsIo Content ()
_writeContentList partner cs = do
	let f = contentListToFragment cs
	updateSequenceNumberSmart partner
	writeFragment f

writeContent :: Content -> TlsIo Content ()
writeContent c = do
	let f = contentToFragment c
	writeFragment f

query :: ValidationCacheQueryCallback
query _ _ _ = return ValidationCacheUnknown

add :: ValidationCacheAddCallback
add _ _ _ = return ()