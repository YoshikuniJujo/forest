{-# LANGUAGE OverloadedStrings, ScopedTypeVariables #-}

module TlsClient (
	TlsServer,
	openTlsServer, tPut, tGetByte, tGetLine, tGet, tGetContent, tClose,

	Option(..),
) where

import System.IO
import Control.Applicative
import Control.Monad
import Data.List
import Data.Word
import qualified Data.ByteString as BS
import Data.X509
import Data.X509.CertificateStore
import Data.X509.Validation
import Crypto.PubKey.RSA

import Fragment
import Content
import Basic

openTlsServer :: [(PrivateKey, CertificateChain)] -> CertificateStore -> Handle
	-> [Option] -> IO TlsServer
openTlsServer ccs certStore sv opts = runOpen (handshake ccs certStore opts) sv

isIncluded :: (PrivateKey, CertificateChain) -> [DistinguishedName] -> Bool
isIncluded (_, CertificateChain certs) dns = let
	idn = certIssuerDN . signedObject . getSigned $ last certs in
	idn `elem` dns

helloVersionFromOptions :: [Option] -> (Word8, Word8)
helloVersionFromOptions =
	maybe (3, 3) (\(OptHelloVersion mjr mnr) -> (mjr, mnr)) .
		find isOptHelloVersion

clientVersionFromOptions :: [Option] -> (Word8, Word8)
clientVersionFromOptions =
	maybe (3, 3) (\(OptClientVersion mjr mnr) -> (mjr, mnr)) .
		find isOptClientVersion

handshake :: [(PrivateKey, CertificateChain)] -> CertificateStore
	-> [Option] -> TlsIo Content ()
handshake ccs certStore opts = do

	-------------------------------------------
	--     CLIENT HELLO                      --
	-------------------------------------------
	cr <- Random <$> randomByteString 32
	let ch = clientHello cr
		(helloVersionFromOptions opts)
		(clientVersionFromOptions opts)
	case (OptStartByChangeCipherSpec `elem` opts,
		OptStartByFinished `elem` opts) of
		(True, _) -> writeContent changeCipherSpec
		(_, True) -> writeContent $ ContentHandshake version $
			HandshakeFinished ""
		_ -> writeContent ch
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
	let pmsVer = if OptPmsVerErr `elem` opts then "\x99\x99" else "\x03\x03"
	pms <- (pmsVer `BS.append`) <$> randomByteString 46
	epms' <- encryptRSA pub pms
--	liftIO $ putStrLn $ "Encrypted Pre Master Secret: " ++ show epms'
	generateKeys pms
	let	cke'' = makeClientKeyExchange $ EncryptedPreMasterSecret epms'
	writeContent cke''
	fragmentUpdateHash $ contentToFragment cke''
--	liftIO $ putStrLn $ "KEY EXCHANGE: " ++ show (contentToFragment cke'')
	liftIO $ putStrLn "GENERATE KEYS"

--	debugPrintKeys

	-------------------------------------------
	--     CERTIFICATE VERIFY                --
	-------------------------------------------
	case crtReq of
		Just _ -> do
			signed <- clientVerifySign pk
			writeContent $ makeVerify signed
			fragmentUpdateHash . contentToFragment $ makeVerify signed
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
	writeContent $ finished fhc
	fragmentUpdateHash . contentToFragment $ finished fhc

	-------------------------------------------
	--     SERVER CHANGE CIPHER SPEC         --
	-------------------------------------------
	sccs <- readContent
	when (doesChangeCipherSpec sccs) $ flushCipherSuite Server
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

serverHelloDone :: TlsIo Content (Maybe CertificateRequest)
serverHelloDone = do

	-------------------------------------------
	--     CERTIFICATE REQUEST               --
	-------------------------------------------
	crtReq <- readContent
	liftIO . putStrLn $
		"CERTIFICATE REQUEST: " ++ take 60 (show crtReq) ++ "..."

	unless (doesServerHelloDone crtReq) $ do

	-------------------------------------------
	--     SERVER HELLO DONE                 --
	-------------------------------------------
		shd <- readContent
		liftIO . putStrLn $ "SERVER HELLO DONE: " ++ take 60 (show shd) ++ "..."

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
