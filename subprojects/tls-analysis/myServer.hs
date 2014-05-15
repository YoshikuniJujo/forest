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

	------------------------------------------
	--           CLIENT HELLO               --
	------------------------------------------
	ch <- readContent
	maybe (throwError "No Client Hello") setClientRandom $ clientRandom ch
	output Client cid "Hello" [
		take 60 (show ch) ++ "...",
		maybe "No Version" show $ clientVersion ch,
		maybe "No Random" showRandom $ clientRandom ch ]

	------------------------------------------
	--           SERVER HELLO               --
	------------------------------------------
	sr <- Random <$> randomByteString 32
	writeContentList [
		serverHello sr,
		certificate certChain,
		certificateRequest $ getDistinguishedNames certStore,
		serverHelloDone ]
	setVersion version
	setServerRandom sr
	cacheCipherSuite cipherSuite
	output Server cid "Hello" [show version, show cipherSuite, showRandom sr]

	------------------------------------------
	--          CLIENT KEY EXCHANGE         --
	------------------------------------------
	c1 <- readContent
	c2 <- readContent
	hms <- handshakeMessages
	c3 <- readContent
	let	Right signed'' = sign Nothing hashDescrSHA256 pkys hms
		Just cc@(CertificateChain certs) = certificateChain c1
		Just (EncryptedPreMasterSecret epms) = encryptedPreMasterSecret c2
		Just ds = digitalSign c3
	let 	PubKeyRSA pub = certPubKey .  getCertificate $ head certs
	unless (verify hashDescrSHA256 pub hms ds) $
		throwError "client authentification failed"
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

	------------------------------------------
	--      CLIENT CHANGE CIPHER SPEC       --
	------------------------------------------
	cccs <- readContent
	when (doesChangeCipherSpec cccs) $ flushCipherSuite Client
	output Client cid "Change Cipher Spec" [take 60 $ show cccs]

	------------------------------------------
	--      CLIENT FINISHED                 --
	------------------------------------------
	fhc <- finishedHash Client
	cf <- readContent
	output Client cid "Finished" [show fhc, showHandshake cf]

	------------------------------------------
	--      SERVER CHANGE CIPHER SPEC       --
	------------------------------------------
	writeFragment Client $ contentToFragment changeCipherSpec
	flushCipherSuite Server
	output Server cid "Change Cipher Spec" [show changeCipherSpec]

	------------------------------------------
	--      SERVER FINISHED                 --
	------------------------------------------
	sf <- finishedHash Server
	writeFragment Client . contentToFragment $ finished sf
	output Server cid "Finished" [showHandshake $ finished sf]

	------------------------------------------
	--      CLIENT GET                      --
	------------------------------------------
	g <- readContent
	output Client cid "GET" [take 60 (show g) ++ "..."]

	------------------------------------------
	--      SERVER CONTENT                  --
	------------------------------------------
	writeContent Client $ applicationData answer
	output Server cid "Contents"
		[take 60 (show $ applicationData answer) ++ "..."]

readContent :: TlsIO Content Content
readContent = do
	c <- readCached Client (readContentList Client)
		<* updateSequenceNumberSmart Client
	fragmentUpdateHash $ contentToFragment c
	return c

readContentList :: Partner -> TlsIO Content [Content]
readContentList partner =
	(\(Right c) -> c) .  fragmentToContent <$> readFragmentNoHash partner

writeContentList :: [Content] -> TlsIO Content ()
writeContentList cs = do
	let f = contentListToFragment cs
	updateSequenceNumberSmart Client
	writeFragment Client f
	fragmentUpdateHash f

writeContent :: Partner -> Content -> TlsIO Content ()
writeContent partner c = do
	let f = contentToFragment c
	writeFragment partner f
	fragmentUpdateHash f

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

getDistinguishedNames :: CertificateStore -> [DistinguishedName]
getDistinguishedNames cs =
	map (certIssuerDN .  signedObject . getSigned) $ listCertificates cs
