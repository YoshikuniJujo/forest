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
import Content hiding (serverHelloDone)
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
	let	client = ClientHandle undefined
		server = ServerHandle sv
	evalTlsIO (run cid pkys certChain) ep cid client server pk
	return ()

run :: Int -> PrivateKey -> CertificateChain -> TlsIO Content ()
run _cid pkys certChain = do

	-------------------------------------------
	--     CLIENT HELLO                      --
	-------------------------------------------
	cr <- Random <$> randomByteString 32
	let ch' = clientHello cr
	writeContent Server ch'
	fragmentUpdateHash $ contentToFragment ch'
	maybe (throwError "No Client Hello") setClientRandom $ clientRandom ch'

	-------------------------------------------
	--     SERVER HELLO                      --
	-------------------------------------------
	sh <- readContent Server
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
			writeContent Server $ certificate certChain
			fragmentUpdateHash . contentToFragment $ certificate certChain
		_ -> return ()

	-------------------------------------------
	--     CLIENT KEY EXCHANGE               --
	-------------------------------------------
	pms <- randomByteString 48
	epms' <- encryptRSA pub pms
	generateMasterSecret pms
	let	cke'' = makeClientKeyExchange $ EncryptedPreMasterSecret epms'
	writeContent Server cke''
	fragmentUpdateHash $ contentToFragment cke''
	debugKeysStr <- debugShowKeys
	liftIO $ mapM_ putStrLn debugKeysStr

	-------------------------------------------
	--     CERTIFICATE VERIFY                --
	-------------------------------------------
	case crtReq of
		Just _ -> do
			hms <- handshakeMessages
			let	Right signed = sign Nothing hashDescrSHA256 pkys hms
			writeContent Server $ makeVerify signed
			fragmentUpdateHash . contentToFragment $ makeVerify signed
		_ -> return ()

	-------------------------------------------
	--     CLIENT CHANGE CIPHER SPEC         --
	-------------------------------------------
	writeContent Server changeCipherSpec
	fragmentUpdateHash $ contentToFragment changeCipherSpec
	flushCipherSuite Client

	-------------------------------------------
	--     CLIENT FINISHED                   --
	-------------------------------------------
	fhc <- finishedHash Client
	writeContent Server $ finished fhc
	fragmentUpdateHash . contentToFragment $ finished fhc

	-------------------------------------------
	--     SERVER CHANGE CIPHER SPEC         --
	-------------------------------------------
	sccs <- readContent Server
	when (doesChangeCipherSpec sccs) $ flushCipherSuite Server
	liftIO . putStrLn $ "SERVER CHANGE CIPHER SPEC: " ++ take 60 (show sccs)

	-------------------------------------------
	--     SERVER FINISHED                   --
	-------------------------------------------
	sfhc <- finishedHash Server
	scf <- readContent Server
	updateSequenceNumberSmart Server
	sfinish <- maybe (throwError $ "Not Finished: " ++ show scf)
		return $ getFinish scf
	liftIO $ do
		putStrLn $ "SERVER FINISHED FIREFOX     : " ++ take 60 (show sfinish)
		putStrLn $ "SERVER FINISHED CALCULATE   : " ++ take 60 (show sfhc)

	-------------------------------------------
	--     CLIENT GET                        --
	-------------------------------------------
	writeContent Server $ applicationData getRequest

	-------------------------------------------
	--     SERVER CONTENTS                   --
	-------------------------------------------
	cnt <- readContent Server
	liftIO . putStrLn $ "SERVER CONTENTS: " ++ take 60 (show cnt) ++ "..."

serverHelloDone :: TlsIO Content (Maybe CertificateRequest)
serverHelloDone = do

	-------------------------------------------
	--     CERTIFICATE REQUEST               --
	-------------------------------------------
	crtReq <- readContent Server
	liftIO . putStrLn $
		"CERTIFICATE REQUEST: " ++ take 60 (show crtReq) ++ "..."

	if doesServerHelloDone crtReq then return () else do

	-------------------------------------------
	--     SERVER HELLO DONE                 --
	-------------------------------------------
		shd <- readContent Server
		liftIO . putStrLn $ "SERVER HELLO DONE: " ++ take 60 (show shd) ++ "..."

	return $ getCertificateRequest crtReq

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

readContent :: Partner -> TlsIO Content Content
readContent partner = do
	c <- readCached partner (readContentList partner)
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

writeContent :: Partner -> Content -> TlsIO Content ()
writeContent partner c = do
	let f = contentToFragment c
	writeFragment partner f

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
