{-# LANGUAGE PackageImports, OverloadedStrings #-}

module Main (main) where

import Control.Monad.IO.Class

import Control.Applicative
import Control.Monad
import Control.Concurrent
import System.Environment
import System.IO.Unsafe
import Data.IORef
import Data.X509.File
import Data.X509

import Network

import Fragment
import Content
import Basic

import "crypto-random" Crypto.Random
import qualified Data.ByteString as BS

import Data.X509.CertificateStore
import Data.X509.Validation

import Crypto.PubKey.RSA
import Crypto.PubKey.RSA.PKCS15
import Crypto.PubKey.HashDescr

main :: IO ()
main = do
	cidRef <- newIORef 0
	certChain <- CertificateChain <$> readSignedObject "localhost.crt"
	[PrivKeyRSA pk] <- readKeyFile "localhost.key"
	certStore <- makeCertificateStore <$> readSignedObject "cacert.pem"
	[PrivKeyRSA pkys] <- readKeyFile "yoshikuni.key"
	[pcl] <- mapM ((PortNumber . fromInt <$>) . readIO) =<< getArgs
	scl <- listenOn pcl
	forever $ do
		cid <- readIORef cidRef
		modifyIORef cidRef succ
		client <- ClientHandle . fst3 <$> accept scl
		let server = ServerHandle undefined
		_ <- forkIO $ do
			ep <- createEntropyPool
			(\act -> evalTlsIO act ep cid client server pk) $
				run certStore certChain pkys cid
		return ()
			
run :: CertificateStore -> CertificateChain -> PrivateKey -> Int -> TlsIO Content ()
run certStore certChain pkys cid = do
	ch <- peekContent Client
	maybe (throwError "No Client Hello") setClientRandom $ clientRandom ch
	output Client cid "Hello" [
		take 60 (show ch) ++ "...",
		maybe "No Version" show $ clientVersion ch,
		maybe "No Random" showRandom $ clientRandom ch ]

	sr <- Random <$> randomByteString 32
	let	certs1 = listCertificates certStore
		dns = map (certIssuerDN .  signedObject . getSigned) certs1
	writeContentList Client [
		serverHello sr,
		certificate certChain,
		certificateRequest dns,
		serverHelloDone ]
	setVersion version
	cacheCipherSuite cipherSuite
	setServerRandom sr
	output Server cid "Hello" [show version, show cipherSuite, showRandom sr]

	hms <- handshakeMessages
	c1@(ContentHandshake _ hs1) <- peekContent Client
	c2@(ContentHandshake _ hs2) <- peekContent Client
	c3 <- peekContent Client
	let	hms' = BS.concat $ hms : [toByteString hs1, toByteString hs2]
		Right signed'' = sign Nothing hashDescrSHA256 pkys hms'
		Just ds = digitalSign c3
		Just (EncryptedPreMasterSecret epms) = encryptedPreMasterSecret c2
		Just cc@(CertificateChain certs) = certificateChain c1
	let 	PubKeyRSA pub = certPubKey .  getCertificate $ head certs
	unless (verify hashDescrSHA256 pub hms' ds) $
		throwError "client authentificatio failed"
	pms <- decryptRSA epms
	generateMasterSecret pms
	v <- liftIO $ validateDefault certStore
		(ValidationCache query add) ("Yoshikuni", "Yoshio") cc
	debugKeysStr <- debugShowKeys
	output Client cid "Key Exchange" $ [
			take 60 (show c1) ++ " ...",
			take 60 (show c2) ++ " ...",
			take 60 (show c3) ++ " ...",
			if null v then "Validate Success" else "Validate Failure",
			"local sign   : " ++ take 50 (show signed'') ++ " ...",
			"recieved sign: " ++ take 50 (show ds) ++ " ..." ]
		++ debugKeysStr

	cccs <- peekContent Client
	when (doesChangeCipherSpec cccs) $ flushCipherSuite Client
	output Client cid "Change Cipher Spec" [take 60 $ show cccs]

	fhc <- finishedHash Client
	cf <- peekContent Client
	output Client cid "Finished"
		[show fhc, show $ (\(ContentHandshake _ h) -> h) cf]

	writeFragment Client $ contentToFragment changeCipherSpec
	flushCipherSuite Server
	output Server cid "Change Cipher Spec" [show changeCipherSpec]

	sf <- finishedHash Server
	writeFragment Client $ contentToFragment $ finished sf
	output Server cid "Finished"
		[show . (\(ContentHandshake _ h) -> h) $ finished sf]

	when (cid == 1) $ do
		g <- peekContent Client
		output Client cid "GET" [take 60 (show g) ++ "..."]
		writeFragment Client $ contentToFragment $ applicationData answer
		output Server cid "Contents"
			[take 60 (show $ applicationData answer) ++ "..."]

peekContent :: Partner -> TlsIO Content Content
peekContent partner = do
	c <- readContent partner
	let f = contentToFragment c
	updateSequenceNumberSmart partner
	fragmentUpdateHash f
	return c

readContent :: Partner -> TlsIO Content Content
readContent partner = readCached $ readContentList partner

readContentList :: Partner -> TlsIO Content [Content]
readContentList partner = do
	Right c <- fragmentToContent <$> readFragmentNoHash partner
	return c

writeContentList :: Partner -> [Content] -> TlsIO Content ()
writeContentList partner cs = do
	let f = contentListToFragment cs
	updateSequenceNumberSmart partner
	writeFragment partner f
	fragmentUpdateHash f

{-
writeContent :: Partner -> Content -> TlsIO Content ()
writeContent partner c = do
	let f = contentToFragment c
	writeFragment partner f
	fragmentUpdateHash f
	-}

answer :: BS.ByteString
answer = BS.concat [
	"HTTP/1.1 200 OK\r\n",
	"Transfer-Encoding: chunked\r\n",
	"Date: Wed, 07 May 2014 02:27:34 GMT\r\n",
	"Server: Warp/2.1.4\r\n",
	"Content-Type: text/plain\r\n\r\n",
	"004\r\n",
	"PONC\r\n",
	"0\r\n\r\n"
 ]

query :: ValidationCacheQueryCallback
query _ _ _ = return ValidationCacheUnknown

add :: ValidationCacheAddCallback
add _ _ _ = return ()

output :: Partner -> Int -> String -> [String] -> TlsIO Content ()
output partner cid msg strs = do
	begin
	liftIO . mapM_ putStr $ map (unlines . map ("\t" ++) . lines) strs
	end
	where
	begin = liftIO $ do
		readChan locker
		putStrLn $ replicate 10 '-' ++ " " ++ show partner ++ "(" ++
			show cid ++ ") " ++ msg ++ " " ++ replicate 10 '-'
	end = liftIO $ putStrLn "" >> writeChan locker ()

locker :: Chan ()
locker = unsafePerformIO $ ((>>) <$> (`writeChan` ()) <*> return) =<< newChan
