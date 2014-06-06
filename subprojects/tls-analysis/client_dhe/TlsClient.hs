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

import Fragment
import Content
import Basic

import qualified Crypto.PubKey.DH as DH

openTlsServer :: [(RSA.PrivateKey, CertificateChain)] -> CertificateStore
	-> Handle -> [CipherSuite]
	-> IO TlsServer
openTlsServer ccs certStore sv cs = runOpen (handshake ccs certStore cs) sv

isIncluded :: (RSA.PrivateKey, CertificateChain) -> [DistinguishedName] -> Bool
isIncluded (_, CertificateChain certs) dns = let
	idn = certIssuerDN . signedObject . getSigned $ last certs in
	idn `elem` dns

handshake :: [(RSA.PrivateKey, CertificateChain)] -> CertificateStore ->
	[CipherSuite] -> TlsIo Content ()
handshake ccs certStore cs = do

	-------------------------------------------
	--     CLIENT HELLO                      --
	-------------------------------------------
	cr <- Random <$> randomByteString 32
	let ch = clientHello cr (3, 3) (3, 3)
		(cs ++ [CipherSuite RSA AES_128_CBC_SHA])
		[CompressionMethodNull]
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
		PubKeyRSA pub = certPubKey $ getCertificate cert
	v <- liftIO $ validateDefault certStore
		(ValidationCache query add) ("localhost", "localhost da") scc
	liftIO . putStrLn $ "VALIDATE RESULT: " ++ show v
	unless (null v) $ throwError "SERVER VALIDATION FAILURE"
	liftIO . putStrLn $ "CERTIFICATE: " ++ take 60 (show crt) ++ "..."
	liftIO . putStrLn $ "CERTIFICATE Chain: " ++ take 60 (show scc) ++ "..."
	liftIO . putStrLn $ "PUBKEY: " ++ take 60 (show pub) ++ "..."

	-------------------------------------------
	--     CERTIFICATE REQUEST               --
	-------------------------------------------
	-------------------------------------------
	--     SERVER HELLO DONE                 --
	-------------------------------------------
	(crtReq, yc, dhsk) <- serverHelloDone pub

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
	generateKeys dhsk
	let	cke'' = makeClientKeyExchange $ EncryptedPreMasterSecret yc
	writeContent cke''
	fragmentUpdateHash $ contentToFragment cke''
	liftIO $ putStrLn "GENERATE KEYS"

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

serverHelloDone :: RSA.PublicKey -> TlsIo Content (Maybe CertificateRequest, BS.ByteString, BS.ByteString)
serverHelloDone pub = do

	-------------------------------------------
	--     CERTIFICATE REQUEST               --
	-------------------------------------------
	cske <- readContent
	liftIO . putStrLn $
		"CERTIFICATE REQUEST: " ++ show cske

	let	ContentHandshake _ (HandshakeServerKeyExchange ske_) = cske
		Right ske = decodeServerKeyExchange ske_
		ServerKeyExchange ps ys _ _ _ _ = ske

	cr <- getClientRandom
	sr <- getServerRandom
	liftIO . print $ verifyServerKeyExchange pub cr sr ske

	g <- getRandomGen
	let	(pr, g') = DH.generatePrivate g ps
		dhsk = calculateCommon ps pr ys
	setRandomGen g'
	liftIO . putStrLn $ "PRIVATE NUMBER: " ++ show pr
	liftIO . putStrLn $ "SHARED KEY    : " ++ show dhsk

	crtReq <- readContent

	unless (doesServerHelloDone crtReq) $ do

	-------------------------------------------
	--     SERVER HELLO DONE                 --
	-------------------------------------------
		shd <- readContent
		liftIO . putStrLn $ "SERVER HELLO DONE: " ++ take 60 (show shd) ++ "..."

	return (
		getCertificateRequest crtReq,
		encodePublic ps $ DH.calculatePublic ps pr,
		dhsk)

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
