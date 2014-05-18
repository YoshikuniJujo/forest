{-# LANGUAGE PackageImports #-}

import System.Environment
import System.IO
import Control.Concurrent
import Control.Applicative
import Control.Monad
import Data.IORef
import Data.X509
import Data.X509.File
import Network
import "crypto-random" Crypto.Random
import Crypto.PubKey.RSA
import Crypto.PubKey.RSA.PKCS15
import Crypto.PubKey.HashDescr

import Fragment
import Content

main :: IO ()
main = do
	cidRef <- newIORef 0
	clpn : svpn : _ <- getArgs
	[PrivKeyRSA pk] <- readKeyFile "localhost.key"
	[PrivKeyRSA pkys] <- readKeyFile "yoshikuni.key"
	sock <- listenOn . PortNumber . fromIntegral $ read clpn
	forever $ do
		cid <- readIORef cidRef
		modifyIORef cidRef succ
		(cl, _, _) <- accept sock
		ep <- createEntropyPool
		sv <- connectTo "localhost" (PortNumber . fromIntegral $ read svpn)
		let	client = ClientHandle cl
			server = ServerHandle sv
		forkIO $ -- do
			evalTlsIO (run cid pkys) ep cid client server pk
--			forkIO $ evalTlsIO c2s ep cid client server pk
--			evalTlsIO s2c ep cid client server pk

run :: Int -> PrivateKey -> TlsIO Content ()
run cid pkys = do

	-------------------------------------------
	--     CLIENT HELLO                      --
	-------------------------------------------
	ch <- readContent Client
	writeContent Server ch
	maybe (throwError "No Client Hello") setClientRandom $ clientRandom ch
	liftIO . putStrLn $ "CLIENT HELLO: " ++ take 60 (show ch) ++ "..."

	-------------------------------------------
	--     SERVER HELLO                      --
	-------------------------------------------
	sh <- readContent Server
	writeContent Client sh
	maybe (throwError "No Server Hello") setVersion $ serverVersion sh
	maybe (throwError "No Server Hello") setServerRandom $ serverRandom sh
	maybe (throwError "No Server Hello") cacheCipherSuite $ serverCipherSuite sh
	liftIO . putStrLn $ "SERVER HELLO: " ++ take 60 (show sh) ++ "..."

	-------------------------------------------
	--     SERVER CERTIFICATE                --
	-------------------------------------------
	crt <- readContent Server
	writeContent Client crt
	liftIO . putStrLn $ "CERTIFICATE: " ++ take 60 (show crt) ++ "..."

	-------------------------------------------
	--     CERTIFICATE REQUEST               --
	-------------------------------------------
	crtReq <- readContent Server
	writeContent Client crtReq
	liftIO . putStrLn $
		"CERTIFICATE REQUEST: " ++ take 60 (show crtReq) ++ "..."

	-------------------------------------------
	--     SERVER HELLO DONE                 --
	-------------------------------------------
	shd <- readContent Server
	writeContent Client shd
	liftIO . putStrLn $ "SERVER HELLO DONE: " ++ take 60 (show shd) ++ "..."

	-------------------------------------------
	--     CLIENT CERTIFICATE                --
	-------------------------------------------
	cCrt <- readContent Client
	writeContent Server cCrt
	let Just cc@(CertificateChain certs) = certificateChain cCrt
	liftIO . putStrLn $
		"CLIENT CERTIFICATE: " ++ take 60 (show cCrt) ++ "..."

	-------------------------------------------
	--     CLIENT KEY EXCHANGE               --
	-------------------------------------------
	cke <- readContent Client
	writeContent Server cke
	let Just (EncryptedPreMasterSecret epms) = encryptedPreMasterSecret cke
	liftIO . putStrLn $
		"KEY EXCHANGE: " ++ take 60 (show cke) ++ "..."
	pms <- decryptRSA epms
	generateMasterSecret pms
	debugKeysStr <- debugShowKeys
	liftIO $ mapM_ putStrLn debugKeysStr

	-------------------------------------------
	--     CERTIFICATE VERIFY                --
	-------------------------------------------
	hms <- handshakeMessages
	cv <- readContent Client
	writeContent Server cv
	let	Just ds = digitalSign cv
		Right signed = sign Nothing hashDescrSHA256 pkys hms
	liftIO $ do
		putStrLn $ "FIREFOX  : " ++ take 60 (show ds) ++ "..."
		putStrLn $ "CALCULATE: " ++ take 60 (show signed) ++ "..."
	liftIO . putStrLn $
		"CERTIFICATE VERIFY: " ++ take 60 (show cv) ++ "..."

	-------------------------------------------
	--     CLIENT CHANGE CIPHER SPEC         --
	-------------------------------------------
	cccs <- readContent Client
	writeContent Server cccs
	when (doesChangeCipherSpec cccs) $ flushCipherSuite Client
	liftIO . putStrLn $ "CHANGE CIPHER SPEC: " ++ take 60 (show cccs)

	-------------------------------------------
	--     CLIENT FINISHED                   --
	-------------------------------------------
	fhc <- finishedHash Client
	cf <- readContent Client
	writeContent Server cf
	finish <- maybe (throwError "Not Finished") return $ getFinish cf
	liftIO $ do
		putStrLn $ "FINISHED FIREFOX     : " ++ take 60 (show finish)
		putStrLn $ "FINISHED CALCULATE   : " ++ take 60 (show fhc)

	-------------------------------------------
	--     SERVER CHANGE CIPHER SPEC         --
	-------------------------------------------
	sccs <- readContent Server
	writeContent Client sccs
	when (doesChangeCipherSpec sccs) $ flushCipherSuite Server
	liftIO . putStrLn $ "SERVER CHANGE CIPHER SPEC: " ++ take 60 (show sccs)

	-------------------------------------------
	--     SERVER FINISHED                   --
	-------------------------------------------
	sfhc <- finishedHash Server
	scf <- readContent Server
	writeContent Client scf
	sfinish <- maybe (throwError "Not Finished") return $ getFinish scf
	liftIO $ do
		putStrLn $ "SERVER FINISHED FIREFOX     : " ++ take 60 (show sfinish)
		putStrLn $ "SERVER FINISHED CALCULATE   : " ++ take 60 (show sfhc)

	-------------------------------------------
	--     CLIENT GET                        --
	-------------------------------------------
	g <- readContent Client
	writeContent Server g
	liftIO . putStrLn $ "CLIENT GET: " ++ take 60 (show g) ++ "..."

	-------------------------------------------
	--     SERVER CONTENTS                   --
	-------------------------------------------
	cnt <- readContent Server
	writeContent Client cnt
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

readContent :: Partner -> TlsIO Content Content
readContent partner = do
	c <- readCached partner (readContentList partner)
--		<* updateSequenceNumberSmart partner
	fragmentUpdateHash $ contentToFragment c
	return c

readContentList :: Partner -> TlsIO Content [Content]
readContentList partner = do
	ret <- fragmentToContent <$> readFragmentNoHash partner
	case ret of
		Right r -> return r
		Left err -> error err

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
