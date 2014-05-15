{-# LANGUAGE PackageImports, OverloadedStrings #-}

import System.Environment
import Control.Applicative
import Control.Monad
import Data.IORef
import qualified Data.ByteString as BS
import Data.X509
import Data.X509.File
import Network
import "crypto-random" Crypto.Random
import Crypto.PubKey.RSA
import Crypto.PubKey.RSA.PKCS15
import Crypto.PubKey.HashDescr

import Fragment
import Content
import Basic

main :: IO ()
main = do
	cidRef <- newIORef 0
	svpn : _ <- getArgs
	[PrivKeyRSA pk] <- readKeyFile "localhost.key"
	[PrivKeyRSA pkys] <- readKeyFile "yoshikuni.key"
	certChain <- CertificateChain <$> readSignedObject "yoshikuni.crt"
	cid <- readIORef cidRef
	modifyIORef cidRef succ
	ep <- createEntropyPool
	sv <- connectTo "localhost"
		(PortNumber $ fromIntegral (read svpn :: Int))
	let	client = ClientHandle undefined -- cl
		server = ServerHandle sv
	evalTlsIO (run cid pkys certChain) ep cid client server pk
	return ()

run :: Int -> PrivateKey -> CertificateChain -> TlsIO Content ()
run _cid pkys certChain = do

	-------------------------------------------
	--     CLIENT HELLO                      --
	-------------------------------------------
	cr <- Random <$> randomByteString 32
--	ch <- readContentNoHash Client
	let ch' = clientHello cr
	writeContent Server ch'
	fragmentUpdateHash $ contentToFragment ch'
	maybe (throwError "No Client Hello") setClientRandom $ clientRandom ch'
--	liftIO . putStrLn $ "CLIENT HELLO: " ++ take 60 (show ch) ++ "..."

	-------------------------------------------
	--     SERVER HELLO                      --
	-------------------------------------------
	sh <- readContent Server
--	writeContent Client sh
	maybe (throwError "No Server Hello") setVersion $ serverVersion sh
	maybe (throwError "No Server Hello") setServerRandom $ serverRandom sh
	maybe (throwError "No Server Hello") cacheCipherSuite $ serverCipherSuite sh
	liftIO . putStrLn $ "SERVER HELLO: " ++ take 60 (show sh) ++ "..."

	-------------------------------------------
	--     SERVER CERTIFICATE                --
	-------------------------------------------
	crt <- readContent Server
	let	Just scc@(CertificateChain (cert : _)) = certificateChain crt
		PubKeyRSA pub = certPubKey $ getCertificate cert
--	writeContent Client crt
	liftIO . putStrLn $ "CERTIFICATE: " ++ take 60 (show crt) ++ "..."
	liftIO . putStrLn $ "CERTIFICATE Chain: " ++ take 60 (show scc) ++ "..."
	liftIO . putStrLn $ "PUBKEY: " ++ take 60 (show pub) ++ "..."

	-------------------------------------------
	--     CERTIFICATE REQUEST               --
	-------------------------------------------
	crtReq <- readContent Server
--	writeContent Client crtReq
	liftIO . putStrLn $
		"CERTIFICATE REQUEST: " ++ take 60 (show crtReq) ++ "..."

	-------------------------------------------
	--     SERVER HELLO DONE                 --
	-------------------------------------------
	shd <- readContent Server
--	writeContent Client shd
	liftIO . putStrLn $ "SERVER HELLO DONE: " ++ take 60 (show shd) ++ "..."

	-------------------------------------------
	--     CLIENT CERTIFICATE                --
	-------------------------------------------
--	cCrt <- readContentNoHash Client
--	writeContent Server cCrt
--	let Just cc = certificateChain cCrt
	writeContent Server $ certificate certChain
	fragmentUpdateHash . contentToFragment $ certificate certChain
--	liftIO . putStrLn $
--		"CLIENT CERTIFICATE: " ++ take 60 (show cCrt) ++ "..."

	-------------------------------------------
	--     CLIENT KEY EXCHANGE               --
	-------------------------------------------
--	cke <- readContentNoHash Client
--	let Just (EncryptedPreMasterSecret epms) = encryptedPreMasterSecret cke
--	liftIO . putStrLn $
--		"KEY EXCHANGE: " ++ take 60 (show cke) ++ "..."
--	pms <- decryptRSA epms

	pms <- randomByteString 48
	epms' <- encryptRSA pub pms
--	pms' <- decryptRSA epms'
	generateMasterSecret pms

--	let	cke'  = makeClientKeyExchange $ EncryptedPreMasterSecret epms
	let	cke'' = makeClientKeyExchange $ EncryptedPreMasterSecret epms'

	writeContent Server cke''
	fragmentUpdateHash $ contentToFragment cke''

	debugKeysStr <- debugShowKeys
--	liftIO . putStrLn $ "EPMS : " ++ show epms
--	liftIO . putStrLn $ "PMS  : " ++ show pms
--	liftIO . putStrLn $ "PMS' : " ++ show pms'
--	liftIO . putStrLn $ "PMS LENGTH: " ++ show (BS.length pms)
	liftIO $ mapM_ putStrLn debugKeysStr

	-------------------------------------------
	--     CERTIFICATE VERIFY                --
	-------------------------------------------
	hms <- handshakeMessages
--	cv <- readContentNoHash Client
--	writeContent Server cv
--	let	Just ds = digitalSign cv
	let	Right signed = sign Nothing hashDescrSHA256 pkys hms
	writeContent Server $ makeVerify signed
	fragmentUpdateHash . contentToFragment $ makeVerify signed
--	fragmentUpdateHash . contentToFragment $ makeVerify signed
--	liftIO $ do
--		putStrLn $ "FIREFOX  : " ++ take 60 (show ds) ++ "..."
--		putStrLn $ "CALCULATE: " ++ take 60 (show signed) ++ "..."
--	liftIO . putStrLn $
--		"CERTIFICATE VERIFY: " ++ take 60 (show cv) ++ "..."

	-------------------------------------------
	--     CLIENT CHANGE CIPHER SPEC         --
	-------------------------------------------
--	cccs <- readContent Client
	writeContent Server changeCipherSpec
	fragmentUpdateHash $ contentToFragment changeCipherSpec
--	writeContent Server cccs
	flushCipherSuite Client
--	when (doesChangeCipherSpec cccs) $ flushCipherSuite Client
--	liftIO . putStrLn $ "CHANGE CIPHER SPEC: " ++ take 60 (show cccs)

	-------------------------------------------
	--     CLIENT FINISHED                   --
	-------------------------------------------
	fhc <- finishedHash Client
--	cf <- readContent Client
--	writeContent Server cf
	writeContent Server $ finished fhc
	fragmentUpdateHash . contentToFragment $ finished fhc
--	finish <- maybe (throwError "Not Finished") return $ getFinish cf
--	liftIO $ do
--		putStrLn $ "FINISHED FIREFOX     : " ++ take 60 (show finish)
--		putStrLn $ "FINISHED CALCULATE   : " ++ take 60 (show fhc)

	-------------------------------------------
	--     SERVER CHANGE CIPHER SPEC         --
	-------------------------------------------
	sccs <- readContent Server
--	writeContent Client sccs
	when (doesChangeCipherSpec sccs) $ flushCipherSuite Server
	liftIO . putStrLn $ "SERVER CHANGE CIPHER SPEC: " ++ take 60 (show sccs)

	-------------------------------------------
	--     SERVER FINISHED                   --
	-------------------------------------------
	sfhc <- finishedHash Server
	scf <- readContent Server
--	writeContent Client scf
	updateSequenceNumberSmart Server
	sfinish <- maybe (throwError $ "Not Finished: " ++ show scf)
		return $ getFinish scf
	liftIO $ do
		putStrLn $ "SERVER FINISHED FIREFOX     : " ++ take 60 (show sfinish)
		putStrLn $ "SERVER FINISHED CALCULATE   : " ++ take 60 (show sfhc)

	-------------------------------------------
	--     CLIENT GET                        --
	-------------------------------------------
--	g <- readContent Client
	writeContent Server $ applicationData getRequest
--	liftIO . putStrLn $ "CLIENT GET: " ++ take 60 (show g) ++ "..."

	-------------------------------------------
	--     SERVER CONTENTS                   --
	-------------------------------------------
	cnt <- readContent Server
--	writeContent Client cnt
	liftIO . putStrLn $ "SERVER CONTENTS: " ++ take 60 (show cnt) ++ "..."

c2s, s2c :: TlsIO Content ()
c2s = forever $ do
	f <- readRawFragment Client
	liftIO . putStrLn $ "CLIENT: " ++ take 60 (show f) ++ "..."
	writeRawFragment Server f

s2c = forever $ do
	f <- readRawFragment Server
	liftIO . putStrLn $ "SERVER: " ++ take 60 (show f) ++ "..."
	writeRawFragment Client f

readContentNoHash :: Partner -> TlsIO Content Content
readContentNoHash partner = readCached partner (readContentList partner)
--		<* updateSequenceNumberSmart partner

readContent :: Partner -> TlsIO Content Content
readContent partner = do
	c <- readCached partner (readContentList partner)
--		<* updateSequenceNumberSmart partner
	fragmentUpdateHash $ contentToFragment c
	return c

readContentList :: Partner -> TlsIO Content [Content]
readContentList partner =
	(\(Right c) -> c) . fragmentToContent <$> readFragmentNoHash partner

writeContentList :: Partner -> [Content] -> TlsIO Content ()
writeContentList partner cs = do
	let f = contentListToFragment cs
	updateSequenceNumberSmart partner
	writeFragment partner f
--	fragmentUpdateHash f

writeContent :: Partner -> Content -> TlsIO Content ()
writeContent partner c = do
	let f = contentToFragment c
	writeFragment partner f
--	fragmentUpdateHash f

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
