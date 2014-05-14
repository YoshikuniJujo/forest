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

import Crypto.PubKey.RSA.PKCS15
import Crypto.PubKey.HashDescr

locker :: Chan ()
locker = unsafePerformIO $ ((>>) <$> (`writeChan` ()) <*> return) =<< newChan

begin :: Partner -> Int -> String -> TlsIO ()
begin partner cid msg = liftIO $ do
	readChan locker
	putStrLn $ replicate 10 '-' ++ " " ++ show partner ++ "(" ++
		show cid ++ ") " ++ msg ++ " " ++ replicate 10 '-'

end :: TlsIO ()
end = liftIO $ putStrLn "" >> writeChan locker ()

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
			(\act -> evalTlsIO act ep cid client server pk) $ do
				begin Client cid "Hello"
				[c1] <- peekContent Client (Just 70)
				let	Just cv = clientVersion c1
					Just cr = clientRandom c1
				setClientRandom cr
				liftIO $ do
					putStrLn . ("\t" ++) $ show cv
					putStr $ showRandom cr
				end

				begin Server cid "Hello"
				sr <- Random <$> randomByteString 32
				writeContent Client $ serverHello sr
				writeContent Client $ certificate certChain
				let	certs1 = listCertificates certStore
					dns = map (certIssuerDN .
						signedObject . getSigned) certs1
				writeContent Client $ certificateRequest dns
				writeContent Client serverHelloDone
				setVersion version
				cacheCipherSuite cipherSuite
				setServerRandom sr
				liftIO $ do
					putStrLn . ("\t" ++) $ show version
					putStrLn . ("\t" ++) $ show cipherSuite
					putStr $ showRandom sr
				end

				begin Client cid "Key Exchange"
				hms <- handshakeMessages
--				[c@(ContentHandshake _ hss)] <- peekContent Client (Just 70)
				[	c1@(ContentHandshake _ hs1),
					c2@(ContentHandshake _ hs2),
					c3@(ContentHandshake _ hs3) ] <-
						peekContent Client (Just 70)
				let	hms'' = BS.concat $ hms : [
						toByteString hs1, toByteString hs2 ]
					Right signed'' = sign Nothing hashDescrSHA256 pkys hms''
					Just ds = digitalSign c3
					Just (EncryptedPreMasterSecret epms) =
						encryptedPreMasterSecret c2
					Just cc@(CertificateChain certs) = certificateChain c1
				liftIO $ do
					v <- validateDefault certStore
						(ValidationCache query add)
						("Yoshikuni", "Yoshio") cc
					putStrLn $ if null v
						then "Validate Success"
						else "Validate Failure"
				liftIO . putStrLn $ "local sign   : " ++
					take 60 (show signed'') ++ " ..."
				liftIO . putStrLn $ "recieved sign: " ++
					take 60 (show ds) ++ " ..."
				let 	PubKeyRSA pub = certPubKey .
						getCertificate $ head certs
				unless (verify hashDescrSHA256 pub hms'' ds) $
					throwError "client authentificatio failed"
				pms <- decryptRSA epms
				generateMasterSecret pms
				debugPrintKeys
				end

				begin Client cid "Change Cipher Spec"
				[cccs] <- peekContent Client Nothing
				when (doesChangeCipherSpec cccs) $
					flushCipherSuite Client
				end

				begin Client cid "Finished"
				finishedHash Client >>= liftIO . print
				_ <- peekContent Client Nothing
				end

				begin Server cid "Change Cipher Spec"
				liftIO $ print changeCipherSpec
				writeFragment Client $
					contentToFragment changeCipherSpec
				flushCipherSuite Server
				end

				begin Server cid "Finished"
				sf <- finishedHash Server
				let sfc = finished sf
				liftIO $ do
					print sf
					print $ (\(ContentHandshake _ h) -> h)
						sfc
				writeFragment Client $ contentToFragment sfc
				end

				when (cid == 1) $ do
					begin Client cid "GET"
					_ <- peekContent Client Nothing
					end
					begin Server cid "Contents"
					let ans = applicationData answer
					liftIO $ print ans
					writeFragment Client $ contentToFragment ans
					end
			return ()
		return ()

peekContent :: Partner -> Maybe Int -> TlsIO [Content]
peekContent partner n = do
	c <- readContent partner n
	let f = map contentToFragment c
	updateSequenceNumberSmart partner
	mapM_ fragmentUpdateHash f
	return c

readContent :: Partner -> Maybe Int -> TlsIO [Content]
readContent partner n = do
	Right c <- fragmentToContent <$> readFragmentNoHash partner
	forM_ c $ liftIO . putStrLn . maybe id (((++ " ...") .) . take) n . show
	return c

writeContent :: Partner -> Content -> TlsIO ()
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
