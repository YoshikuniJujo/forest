{-# LANGUAGE PackageImports, OverloadedStrings #-}

module Main (main) where

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
import Handshake
import PreMasterSecret
import Parts
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
	[PrivKeyRSA pk] <- readKeyFile "localhost.key"
	[PrivKeyRSA pkys] <- readKeyFile "yoshikuni.key"
	certStore <- makeCertificateStore <$> readSignedObject "cacert.pem"
	[pcl, psv] <- mapM ((PortNumber . fromInt <$>) . readIO) =<< getArgs
	scl <- listenOn pcl
	forever $ do
		cid <- readIORef cidRef
		modifyIORef cidRef succ
		client <- ClientHandle . fst3 <$> accept scl
		server <- ServerHandle <$> connectTo "localhost" psv
		forkIO $ do
			ep <- createEntropyPool
			(\act -> evalTlsIO act ep cid client server pk) $ do
				begin Client cid "Hello"
				c1 <- peekContent Client (Just 70)
				let	Just cv = clientVersion c1
					Just cr = clientRandom c1
				setClientRandom cr
				liftIO $ do
					putStrLn . ("\t" ++) $ show cv
					putStr $ showRandom cr
				end

				begin Server cid "Hello"
				c2 <- peekContent Server (Just 70)
				c3 <- peekContent Server Nothing
				c4 <- peekContent Server Nothing
				let	Just sv = serverVersion c2
					Just cs = cipherSuite c2
					Just sr = serverRandom c2
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
				let	hms' = BS.concat $ hms :
						map handshakeToByteString (take 1 hss)
				let	hms'' = BS.concat $ hms :
						map handshakeToByteString (take 2 hss)
--					signed = sign Nothing hashDescrSHA256 pkys hms
--					signed' = sign Nothing hashDescrSHA256 pkys hms'
					signed'' = sign Nothing hashDescrSHA256 pkys hms''
					Just ds = digitalSign c
					Just (EncryptedPreMasterSecret epms) =
						encryptedPreMasterSecret c
					Just cc@(CertificateChain cs) = certificateChain c
--				liftIO $ putStrLn $ "signed: " ++ show signed
--				liftIO $ putStrLn $ "signed': " ++ show signed'
				liftIO $ putStrLn $ "signed'': " ++ show signed''
				liftIO $ putStrLn $ "ds      : " ++ show ds
				liftIO $ validateDefault certStore (ValidationCache query add)
					("Yoshikuni", "Yoshio") cc >>= print
				let 	PubKeyRSA pub = certPubKey .
						getCertificate $ head cs
					sigAlg = certSignatureAlg .
						getCertificate $ head cs

				liftIO $ print pub
				liftIO $ print sigAlg
				liftIO . print $ verify hashDescrSHA256 pub hms'' ds
				pms <- decryptRSA epms
				generateMasterSecret pms
				{-
				liftIO $ do
					print epms
					print pms
					-}
				debugPrintKeys
				end

				begin Client cid "Change Cipher Suite"
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

				begin Server cid "Change Cipher Suite"
				writeFragment Client $ contentToFragment $
					ContentChangeCipherSpec (Version 3 3)
						ChangeCipherSpec
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
				liftIO $ print sf
				writeFragment Client $ contentToFragment $
					ContentHandshake (Version 3 3) $
						[HandshakeRaw HandshakeTypeFinished sf]
--				_ <- peekContent Server Nothing
				end

				when (cid == 1) $ do
					begin Client cid "GET"
					_ <- peekContent Client Nothing
					end
					begin Server cid "Contents"
					let ans = ContentRaw (ContentTypeRaw 23)
						(Version 3 3) answer
					liftIO $ print ans
					writeFragment Client $ contentToFragment $
						ans
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
	Right c <- fragmentToContent <$> readFragment partner
	writeFragment (opponent partner) $ contentToFragment c
	case c of
		ContentHandshake _ hss -> forM_ hss $
			liftIO . putStrLn . maybe id (((++ " ...") .) . take) n . show
		_ -> liftIO . putStrLn .
			maybe id (((++ " ...") .) . take) n $ show c
	return c

peekRawFragment :: Partner -> TlsIO () -- RawFragment
peekRawFragment partner = do
	f <- readRawFragment partner
	writeRawFragment (opponent partner) f
	liftIO $ print f

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
