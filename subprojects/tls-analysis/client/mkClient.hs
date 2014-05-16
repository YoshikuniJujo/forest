{-# LANGUAGE PackageImports, OverloadedStrings, ScopedTypeVariables #-}

import System.Environment
import Control.Applicative
import Control.Monad
import qualified Data.ByteString as BS
import Data.X509
import Data.X509.File
import Network
-- import "crypto-random" Crypto.Random
import Crypto.PubKey.RSA

import Fragment
import Content
import Basic

main :: IO ()
main = do
	(svpn :: Int) : _ <- mapM readIO =<< getArgs
	[PrivKeyRSA pkys] <- readKeyFile "yoshikuni.key"
	certChain <- CertificateChain <$> readSignedObject "yoshikuni.crt"
--	ep <- createEntropyPool
	sv <- connectTo "localhost" . PortNumber $ fromIntegral svpn
--	evalTlsIo (run pkys certChain) ep sv
	tls <- runOpen (handshake pkys certChain) sv
	tPut tls getRequest
	tGetWhole tls >>= print

run :: PrivateKey -> CertificateChain -> TlsIo Content ()
run pkys certChain = handshake pkys certChain >> getHttp

handshake :: PrivateKey -> CertificateChain -> TlsIo Content ()
handshake pkys certChain = do

	-------------------------------------------
	--     CLIENT HELLO                      --
	-------------------------------------------
	cr <- Random <$> randomByteString 32
	let ch = clientHello cr
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
	liftIO . putStrLn $ "SERVER HELLO: " ++ take 60 (show sh) ++ "..."

	-------------------------------------------
	--     SERVER CERTIFICATE                --
	-------------------------------------------
	crt <- readContent
	let	Just scc@(CertificateChain (cert : _)) = certificateChain crt
		PubKeyRSA pub = certPubKey $ getCertificate cert
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

	-------------------------------------------
	--     CLIENT CERTIFICATE                --
	-------------------------------------------
	case crtReq of
		Just _ -> do
			writeContent $ certificate certChain
			fragmentUpdateHash . contentToFragment $ certificate certChain
		_ -> return ()

	-------------------------------------------
	--     CLIENT KEY EXCHANGE               --
	-------------------------------------------
	pms <- randomByteString 48
	epms' <- encryptRSA pub pms
	generateKeys pms
	let	cke'' = makeClientKeyExchange $ EncryptedPreMasterSecret epms'
	writeContent cke''
	fragmentUpdateHash $ contentToFragment cke''
	liftIO $ putStrLn "GENERATE KEYS"

	-------------------------------------------
	--     CERTIFICATE VERIFY                --
	-------------------------------------------
	case crtReq of
		Just _ -> do
			signed <- clientVerifySign pkys
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

getHttp :: TlsIo Content ()
getHttp = do

	-------------------------------------------
	--     CLIENT GET                        --
	-------------------------------------------
	writeContent $ applicationData getRequest

	-------------------------------------------
	--     SERVER CONTENTS                   --
	-------------------------------------------
	cnt <- readContent
	liftIO . putStrLn $ "SERVER CONTENTS: " ++ take 60 (show cnt) ++ "..."

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
	c <- readCached $ readContentList
	fragmentUpdateHash $ contentToFragment c
	return c

readContentList :: TlsIo Content [Content]
readContentList =
	(\(Right c) -> c) . fragmentToContent <$> readFragment

writeContentList :: Partner -> [Content] -> TlsIo Content ()
writeContentList partner cs = do
	let f = contentListToFragment cs
	updateSequenceNumberSmart partner
	writeFragment f

writeContent :: Content -> TlsIo Content ()
writeContent c = do
	let f = contentToFragment c
	writeFragment f

(+++) :: BS.ByteString -> BS.ByteString -> BS.ByteString
(+++) = BS.append

getRequest :: BS.ByteString
getRequest =
	"GET / HTTP/1.1\r\n" +++
	"Host: localhost:4492\r\n" +++
	"User-Agent: Mozilla/5.0 (X11; Linux i686; rv:24.0) " +++
		"Gecko/20140415 Firefox/24.0\r\n" +++
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;" +++
		"q=0.8\r\n" +++
	"Accept-Language: ja,en-us;q=0.7,en;q=0.3\r\n" +++
	"Accept-Encoding: gzip, deflate\r\n" +++
	"Connection: keep-alive\r\n" +++
	"Cache-Control: max-age=0\r\n\r\n"
