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

import DiffieHellman()

openTlsServer :: [(RSA.PrivateKey, CertificateChain)] -> CertificateStore
	-> Handle -> [CipherSuite]
	-> IO TlsServer
openTlsServer ccs certStore sv cs =
	runOpen (const () <$> (helloHandshake ccs certStore cs :: TlsIo Content ())) sv

isIncluded :: (RSA.PrivateKey, CertificateChain) -> [DistinguishedName] -> Bool
isIncluded (_, CertificateChain certs) dns = let
	idn = certIssuerDN . signedObject . getSigned $ last certs in
	idn `elem` dns

helloHandshake :: [(RSA.PrivateKey, CertificateChain)] -> CertificateStore ->
	[CipherSuite] -> TlsIo Content ()
helloHandshake ccs certStore cs = do
	hello cs
	_ :: DH.Params <- handshake ccs certStore
	return ()

hello :: [CipherSuite] -> TlsIo Content ()
hello cs = do

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

handshake :: Base b =>
	[(RSA.PrivateKey, CertificateChain)] -> CertificateStore -> TlsIo Content b
handshake ccs certStore = do

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
	(crtReq, yc, dhsk, b) <- serverHelloDone pub

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
	return b

serverKeyExchange :: Base b => b -> RSA.PublicKey -> TlsIo Content (b, Public b)
serverKeyExchange t pub = do
	if wantPublic t
	then do cske <- readContent
		cr <- getClientRandom
		sr <- getServerRandom
		let	ContentHandshake _ (HandshakeServerKeyExchange ske) = cske
			Right (p, y) = verifyServerKeyExchange pub cr sr ske
		return (p, y)
	else return (undefined, undefined)

serverHelloDone :: Base b => RSA.PublicKey ->
	TlsIo Content (Maybe CertificateRequest, BS.ByteString, BS.ByteString, b)
serverHelloDone pub = do

	-----------------------------------------------
	--      SERVER KEY EXCHANGE                  --
	-----------------------------------------------
	(ps, ys) <- serverKeyExchange undefined pub
	g <- getRandomGen
	let	(pr, g') = generateSecret g ps
		dhsk = calculateCommon ps pr ys
	setRandomGen g'

	-------------------------------------------
	--     CERTIFICATE REQUEST               --
	-------------------------------------------

	crtReq <- readContent

	unless (doesServerHelloDone crtReq) $ do

	-------------------------------------------
	--     SERVER HELLO DONE                 --
	-------------------------------------------
		_ <- readContent
		return ()
	return (
		getCertificateRequest crtReq,
		encodePublic ps $ calculatePublic ps pr, -- DH.calculatePublic ps pr,
		dhsk, ps)

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
