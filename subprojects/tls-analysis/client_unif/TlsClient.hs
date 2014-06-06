{-# LANGUAGE OverloadedStrings, ScopedTypeVariables #-}

module TlsClient (
	TlsServer,
	openTlsServer, tPut, tGetByte, tGetLine, tGet, tGetContent, tClose,
) where

import System.IO
import Control.Applicative
import Control.Monad
import qualified Data.ByteString as BS
import Data.X509
import Data.X509.CertificateStore
import Data.X509.Validation
import qualified Crypto.PubKey.DH as DH
import qualified Crypto.Types.PubKey.ECC as ECC
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA

import Fragment
import Content
import Basic

import Base
import KeyExchange
import DiffieHellman(byteStringToInteger)
import EcDhe

openTlsServer :: SecretKey sk =>
	String -> [(sk, CertificateChain)] -> CertificateStore -> Handle -> [CipherSuite] -> IO TlsServer
openTlsServer name ccs certStore sv cs =
	runOpen (helloHandshake name ccs certStore cs) sv

isIncluded :: (sk, CertificateChain) -> [DistinguishedName] -> Bool
isIncluded (_, CertificateChain certs) dns = let
	idn = certIssuerDN . signedObject . getSigned $ last certs in
	idn `elem` dns

helloHandshake :: SecretKey sk =>
	String -> [(sk, CertificateChain)] -> CertificateStore ->
	[CipherSuite] -> TlsIo Content ()
helloHandshake name ccs certStore css = do
	hello css
	cs <- getCipherSuite
	liftIO . putStrLn $ "CIPHER SUITE: " ++ show cs
	case cs of
		CipherSuite RSA _ -> do
			_ :: NoDh <- handshake False name ccs certStore
			return ()
		CipherSuite DHE_RSA _ -> do
			_ :: DH.Params <- handshake True name ccs certStore
			return ()
		CipherSuite ECDHE_RSA _ -> do
			_ :: Curve <- handshake True name ccs certStore
			return ()
		CipherSuite ECDHE_ECDSA _ -> do
			_ :: Curve <- handshake True name ccs certStore
			return ()
		_ -> throwError "TlsClient.helloHandshake"
	
hello :: [CipherSuite] -> TlsIo Content ()
hello cs = do

	-------------------------------------------
	--     CLIENT HELLO                      --
	-------------------------------------------
	cr <- Random <$> randomByteString 32
	let ch = clientHello cr cs
	writeContent ch
	fragmentUpdateHash $ contentToFragment ch
	maybe (throwError "No Client Hello") setClientRandom $ clientRandom ch

	-------------------------------------------
	--     SERVER HELLO                      --
	-------------------------------------------
	sh <- readContent
	maybe (throwError "No Server Hello") setVersion $ serverVersion sh
	maybe (throwError "No Server Hello") setServerRandom $ serverRandom sh
	maybe (throwError "No Server Hello") cacheCipherSuite $ serverCipherSuite sh
--	liftIO . putStrLn $ "SERVER HELLO: " ++ show sh

serverKeyExchange :: (Base b, PublicKey pk) =>
	pk -> TlsIo Content (b, BS.ByteString, BS.ByteString)
serverKeyExchange pub = do
	(ps, ys) <- exchange undefined
	g <- getRandomGen
	let	(pr, g') = generateSecret g ps
		pv = encodePublic ps $ calculatePublic ps pr
		dhsk = calculateCommon ps pr ys
	setRandomGen g'
	return (ps, pv, dhsk)
	where
	exchange :: Base b => b -> TlsIo Content (b, Public b)
	exchange t =
		if wantPublic t
		then do	cske <- readContent
			Just cr <- getClientRandom
			Just sr <- getServerRandom
			let	ContentHandshake _ (HandshakeServerKeyExchange ske) = cske
			case verifyServerKeyExchange pub cr sr ske of
				Right (p, y) -> return (p, y)
				Left err -> error err
		else return (undefined, undefined)

makeEcdsaPubKey :: ECC.CurveName -> BS.ByteString -> ECDSA.PublicKey
makeEcdsaPubKey cn bs = case cn of
	ECC.SEC_p256r1 -> ECDSA.PublicKey secp256r1 (ECC.Point pubx puby)
	_ -> error "TlsClient.makeEcdsaPubKey"
	where
	(bspubx, bspuby) = BS.splitAt 32 $ BS.tail bs
	[pubx, puby] = map byteStringToInteger [bspubx, bspuby]

handshake :: (Base b, SecretKey sk)  => Bool ->
	String -> [(sk, CertificateChain)] -> CertificateStore ->
	TlsIo Content b
handshake dh name ccs certStore = do

	-------------------------------------------
	--     SERVER CERTIFICATE                --
	-------------------------------------------
	crt <- readContent
	let	Just scc@(CertificateChain (cert : _)) = certificateChain crt
		pb@(~(PubKeyRSA pub)) = certPubKey $ getCertificate cert
	v <- liftIO $ validateDefault certStore
		(ValidationCache query add) (name, "localhost da") scc
--	liftIO . putStrLn $ "VALIDATE RESULT: " ++ show v
	unless (null v) $ throwError "SERVER VALIDATION FAILURE"
--	liftIO . putStrLn $ "CERTIFICATE: " ++ take 60 (show crt) ++ "..."
--	liftIO . putStrLn $ "CERTIFICATE Chain: " ++ take 60 (show scc) ++ "..."
--	liftIO . putStrLn $ "PUBKEY: " ++ take 60 (show pub) ++ "..."

	-------------------------------------------
	--     CERTIFICATE REQUEST               --
	-------------------------------------------
	-------------------------------------------
	--     SERVER HELLO DONE                 --
	-------------------------------------------
	
	(ps, epms, pms) <- if dh
	then case pb of
		PubKeyRSA p -> serverKeyExchange p
		PubKeyECDSA cn p -> serverKeyExchange (makeEcdsaPubKey cn p)
		_ -> error "TlsClient.handshake"
	else do
		p <- ("\x03\x03" `BS.append`) <$> randomByteString 46
		e <- lenBodyToByteString 2 <$> encryptRSA pub p
		return (undefined, e, p)

	crtReq <- serverHelloDone


	let	Just (CertificateRequest _ _ sdn) = crtReq
		(pk, cc) = head $ filter (`isIncluded` sdn) ccs

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
--	liftIO . putStrLn $ "PRE MASTER SECRET: " ++ show pms
	generateKeys pms
	let	cke = ContentHandshake version $ HandshakeClientKeyExchange epms
	writeContent cke
	fragmentUpdateHash $ contentToFragment cke

	-------------------------------------------
	--     CERTIFICATE VERIFY                --
	-------------------------------------------
	case crtReq of
		Just _ -> do
			signed <- clientVerifySign pk
			writeContent $ makeVerify (algorithm pk) signed
			fragmentUpdateHash . contentToFragment $ makeVerify
				(algorithm pk) signed
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
--	liftIO . putStrLn $ "FINISHED HASH: " ++ show fhc
	writeContent $ finished fhc
	fragmentUpdateHash . contentToFragment $ finished fhc

	-------------------------------------------
	--     SERVER CHANGE CIPHER SPEC         --
	-------------------------------------------
	sccs <- readContent
	when (doesChangeCipherSpec sccs) $ flushCipherSuite Server
--	liftIO . putStrLn $ "SERVER CHANGE CIPHER SPEC: " ++ take 60 (show sccs)

	-------------------------------------------
	--     SERVER FINISHED                   --
	-------------------------------------------
	_sfhc <- finishedHash Server
	scf <- readContent
	updateSequenceNumberSmart Server
	_sfinish <- maybe (throwError $ "Not Finished: " ++ show scf)
		return $ getFinish scf
		{-
	liftIO $ do
		putStrLn $ "SERVER FINISHED FIREFOX     : " ++ take 60 (show sfinish)
		putStrLn $ "SERVER FINISHED CALCULATE   : " ++ take 60 (show sfhc)
		-}
	return ps

serverHelloDone :: TlsIo Content (Maybe CertificateRequest)
serverHelloDone = do

	-------------------------------------------
	--     CERTIFICATE REQUEST               --
	-------------------------------------------
	crtReq <- readContent
--	liftIO . putStrLn $
--		"CERTIFICATE REQUEST: " ++ take 60 (show crtReq) ++ "..."

	unless (doesServerHelloDone crtReq) $ do

	-------------------------------------------
	--     SERVER HELLO DONE                 --
	-------------------------------------------
		_shd <- readContent
		return ()
--		liftIO . putStrLn $ "SERVER HELLO DONE: " ++ take 60 (show shd) ++ "..."

	return $ getCertificateRequest crtReq

readContent :: TlsIo Content Content
readContent = do
	c <- readCached readContentList
	fragmentUpdateHash $ contentToFragment c
	return c

readContentList :: TlsIo Content [Content]
readContentList =
	(\(Right c) -> c) . fragmentToContent <$> readFragment

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
