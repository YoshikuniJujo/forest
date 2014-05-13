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

-- import Fragment
import Content
-- import Handshake
-- import ServerHello
-- import CertificateRequest
-- import PreMasterSecret
-- import Parts
import Tools

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
		_ <- forkIO $ do
			ep <- createEntropyPool
			(\act -> evalTlsIO act ep cid client (ServerHandle undefined) pk) $ do
				begin Client cid "Hello"
				c1 <- peekContent Client (Just 70)
				let	Just cv = clientVersion c1
					Just cr = clientRandom c1
--				liftIO $ print c1
				setClientRandom cr
				liftIO $ do
					putStrLn . ("\t" ++) $ show cv
					putStr $ showRandom cr
				end

				begin Server cid "Hello"
				sh' <- handshakeToContent <$> mkServerHello
				writeContent Client sh'
				writeContent Client . handshakeToContent $
					HandshakeCertificate certChain
				let	certs1 = listCertificates certStore
					dns = map (certIssuerDN . signedObject . getSigned) certs1
					cReq' = mkCertReq dns
				writeContent Client $ handshakeToContent cReq'
				writeContent Client $ ContentHandshake (Version 3 3)
					[HandshakeServerHelloDone]
				let	Just sv = serverVersion sh'
					Just cs = cipherSuite sh'
					Just sr = serverRandom sh'
				setVersion sv
				cacheCipherSuite cs
				setServerRandom sr
				liftIO $ do
					putStrLn . ("\t" ++) $ show sv
					putStrLn . ("\t" ++) $ show cs
					putStr $ showRandom sr
				end
				return ()

{-
				begin Client cid "Client Certificate"
				peekContent Client (Just 70)
				end
				-}

				begin Client cid "Key Exchange"
				hms <- handshakeMessages
--				liftIO . putStrLn $ "Messages: " ++ show hms
				c@(ContentHandshake _ hss) <- peekContent Client (Just 70)
				let	hms'' = BS.concat $ hms :
						map handshakeToByteString (take 2 hss)
					Right signed'' = sign Nothing hashDescrSHA256 pkys hms''
					Just ds = digitalSign c
					Just (EncryptedPreMasterSecret epms) =
						encryptedPreMasterSecret c
					Just cc@(CertificateChain certs) = certificateChain c
--				liftIO $ putStrLn $ "signed: " ++ show signed
--				liftIO $ putStrLn $ "signed': " ++ show signed'
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
--					sigAlg = certSignatureAlg .
--						getCertificate $ head certs

--				liftIO $ print pub
--				liftIO $ print sigAlg
				unless (verify hashDescrSHA256 pub hms'' ds) $
					throwError "client authentificatio failed"
				pms <- decryptRSA epms
				generateMasterSecret pms
				{-
				liftIO $ do
					print epms
					print pms
					-}
				debugPrintKeys
				end

				begin Client cid "Change Cipher Spec"
				cccs <- peekContent Client Nothing
				when (doesChangeCipherSpec cccs) $
					flushCipherSuite Client
				end

				begin Client cid "Finished"
				finishedHash Client >>= liftIO . print
				_ <- peekContent Client Nothing
				{-
				RawFragment _ e <- peekRawFragment Client
				d <- decrypt e
				-}
				end

				begin Server cid "Change Cipher Spec"
				let sccs = ContentChangeCipherSpec (Version 3 3)
					ChangeCipherSpec
				liftIO $ print sccs
				writeFragment Client $ contentToFragment sccs
				flushCipherSuite Server
				end

{-
				sccs <- peekContent Server Nothing
				when (doesChangeCipherSpec sccs) $
					flushCipherSuite Server
				end
				-}

				begin Server cid "Finished"
				sf <- finishedHash Server
				let sfc = ContentHandshake (Version 3 3)
					[HandshakeRaw HandshakeTypeFinished sf]
				liftIO $ do
					print sf
					print $ (\(ContentHandshake _ [h]) -> h)
						sfc
				writeFragment Client $ contentToFragment sfc
--				_ <- peekContent Server Nothing
				end

				when (cid == 1) $ do
					begin Client cid "GET"
					_ <- peekContent Client Nothing
					end
					begin Server cid "Contents"
					let ans = ContentApplicationData
						(Version 3 3) answer
					liftIO $ print ans
					writeFragment Client $ contentToFragment ans
					end

{-
			forkIO $ do
				ep <- createEntropyPool
				(\act -> evalTlsIO act ep cid client server pk) $ do
					forever $ do
						f <- readRawFragment Client
						writeRawFragment Server f
						begin Client cid "Others"
						liftIO $ print f
						end
			forkIO $ do
				ep <- createEntropyPool
				(\act -> evalTlsIO act ep cid client server pk) $ do
					forever $ do
						f <- readRawFragment Server
						writeRawFragment Client f
						begin Server cid "Others"
						liftIO $ print f
						end
						-}
			return ()
		return ()

peekContent :: Partner -> Maybe Int -> TlsIO Content
peekContent partner n = do
	c <- readContent partner n
--	writeContent (opponent partner) c
--	fragmentUpdateHash $ contentToFragment c
	let f = contentToFragment c
--	writeFragment (opponent partner) f
	updateSequenceNumberSmart partner
	fragmentUpdateHash f
	return c

readContent :: Partner -> Maybe Int -> TlsIO Content
readContent partner n = do
	Right c <- fragmentToContent <$> readFragmentNoHash partner
--	Right c <- fragmentToContent <$> readFragment partner
	case c of
		ContentHandshake _ hss -> forM_ hss $
			liftIO . putStrLn . maybe id (((++ " ...") .) . take) n . show
		_ -> liftIO . putStrLn .
			maybe id (((++ " ...") .) . take) n $ show c
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

handshakeToContent :: Handshake -> Content
handshakeToContent = ContentHandshake (Version 3 3) . (: [])

mkServerHello :: TlsIO Handshake
mkServerHello = do
	sr <- randomByteString 32
	return . HandshakeServerHello $ ServerHello
		(ProtocolVersion 3 3)
		(Random sr)
		(SessionId "")
		TLS_RSA_WITH_AES_128_CBC_SHA CompressionMethodNull Nothing

mkCertReq :: [DistinguishedName] -> Handshake
mkCertReq dns = HandshakeCertificateRequest $ CertificateRequest
	[ClientCertificateTypeRsaSign]
	[(HashAlgorithmSha256, SignatureAlgorithmRsa)]
	dns
