{-# LANGUAGE PackageImports, OverloadedStrings #-}

module Main (main) where

import Data.Maybe
import Data.Char
import System.IO
import Numeric

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
import ClientHello
import PreMasterSecret
import Parts
import Tools

import "crypto-random" Crypto.Random
import qualified Data.ByteString as BS

import Data.X509.CertificateStore
import Data.X509.Validation

import Crypto.PubKey.RSA.PKCS15
import Crypto.PubKey.HashDescr

locker, lock :: Chan ()
locker = unsafePerformIO $ ((>>) <$> (`writeChan` ()) <*> return) =<< newChan
lock = unsafePerformIO $ ((>>) <$> (`writeChan` ()) <*> return) =<< newChan

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
		_ <- forkIO $ do
			ep <- createEntropyPool
			(\act -> evalTlsIO act ep cid client server pk) $ do
				begin Client cid "Hello"
				c1 <- wantContent Client (Just 70)
--				putContent Server . mkClientHello . fromJust $ clientRandom c1
				putContent Server c1
				let	Just cv = clientVersion c1
					Just cr = clientRandom c1
				setClientRandom cr
				liftIO $ do
					putStrLn . ("\t" ++) $ show cv
					putStr $ showRandom cr
				end

				begin Server cid "Hello"
				c2 <- peekContent Server (Just 70)
				_ <- peekContent Server (Just 70)
				_ <- peekContent Server (Just 70)
				_ <- peekContent Server Nothing
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


				begin Client cid "Key Exchange"
				hms <- handshakeMessages
				c@(ContentHandshake _ hss) <- wantContent Client (Just 70)
				putContent Server c
				let	hms'' = BS.concat $ hms :
						map handshakeToByteString (take 2 hss)
					Right signed'' = sign Nothing hashDescrSHA256 pkys hms''
					Just ds = digitalSign c
					Just (EncryptedPreMasterSecret epms) =
						encryptedPreMasterSecret c
					Just cc@(CertificateChain certs) = certificateChain c
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
					throwError "client authentification failed"
				pms <- decryptRSA epms
				generateMasterSecret pms
				debugPrintKeys
				end

--				when (cid == 0) $ do
--					begin Client cid "Change Cipher Spec"
--					cccs <- peekContent Client Nothing
--					when (doesChangeCipherSpec cccs) $
--						flushCipherSuite Client
--					end

--					begin Client cid "Finished"
--					finishedHash Client >>= liftIO . print
--					_ <- peekContent Client Nothing
--					end

--					begin Server cid "DEBUG"
--					sccs <- peekContent Server (Just 70)
--					liftIO . putStrLn $ "DEBUG :" ++ show c
--					when (doesChangeCipherSpec sccs) $
--						flushCipherSuite Server
--					finishedHash Server >>= liftIO . print
--					peekContent Server (Just 70)
--					return ()

				when (cid == 1) $ do

					begin Client cid "Change Cipher Spec"
					cccs <- wantContent Client Nothing
					putContent Server $ ContentChangeCipherSpec
						(Version 3 3) ChangeCipherSpec
					when (doesChangeCipherSpec cccs) $
						flushCipherSuite Client
					end

					begin Client cid "Finished"
					fhc <- finishedHash Client
					liftIO $ print fhc
					_ <- wantContent Client Nothing
					putContent Server .
						ContentHandshake (Version 3 3) .
							(: []) $
							HandshakeRaw
							HandshakeTypeFinished
							fhc
					end

--					begin Server cid "DEBUG"
					sccs <- peekContent Server (Just 70)
--					liftIO . putStrLn $ "DEBUG :" ++ show c
					when (doesChangeCipherSpec sccs) $
						flushCipherSuite Server
					finishedHash Server >>= liftIO . print
					peekContent Server (Just 70)

					get <- wantContent Client (Just 70)
					putContent Server appDataGet
					peekContent Server (Just 70)
					return ()
--					end

{-
--					begin Client cid "Finished"
					finishedHash Client >>= liftIO . print
					liftIO $ putStrLn "--- DEBUG ---"
					_ <- peekContent Client Nothing
					return ()
--					end
					-}
{-

				begin Server cid "Change Cipher Spec"
				let sccs = ContentChangeCipherSpec (Version 3 3)
					ChangeCipherSpec
				liftIO $ print sccs
				writeFragment Client $ contentToFragment sccs
				flushCipherSuite Server
				end


				begin Server cid "Finished"
				sf <- finishedHash Server
				let sfc = ContentHandshake (Version 3 3)
					[HandshakeRaw HandshakeTypeFinished sf]
				liftIO $ do
					print sf
					print $ (\(ContentHandshake _ [h]) -> h)
						sfc
				writeFragment Client $ contentToFragment sfc
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
-}

				let	ClientHandle cl = client
					ServerHandle sv = server
				liftIO $ do
					forkIO . forever $ do
						c <- hGetChar cl
						readChan lock
						putEscChar 32 c
						writeChan lock ()
						hPutChar sv c
					forever $ do
						c <- hGetChar sv
						readChan lock
						putEscChar 31 c
						writeChan lock ()
						hPutChar cl c

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

wantContent :: Partner -> Maybe Int -> TlsIO Content
wantContent partner n = do
	Right c <- fragmentToContent <$> readFragment partner
	case c of
		ContentHandshake _ hss -> forM_ hss $
			liftIO . putStrLn . maybe id (((++ " ...") .) . take) n . show
		_ -> liftIO . putStrLn .
			maybe id (((++ " ...") .) . take) n $ show c
	return c

putContent :: Partner -> Content -> TlsIO ()
putContent partner c = writeFragment partner $ contentToFragment c

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

{-
sockHandler :: Chan () -> Socket -> PortID -> IO ()
sockHandler lock sock pid = do
	(cl, _, _) <- accept sock
	hSetBuffering cl NoBuffering
	sv <- connectTo "localhost" pid
	forkIO $ commandProcessor lock cl sv
	sockHandler lock sock pid 

commandProcessor :: Chan () -> Handle -> Handle -> IO ()
commandProcessor lock cl sv = do
	hSetBuffering cl NoBuffering
	hSetBuffering sv NoBuffering
	hSetBuffering stdout NoBuffering
	forkIO . forever $ do
		c <- hGetChar cl
		readChan lock
		putEscChar 32 c
		writeChan lock ()
		hPutChar sv c
	forkIO . forever $ do
		c <- hGetChar sv
		readChan lock
		putEscChar 31 c
		writeChan lock ()
		hPutChar cl c
	return ()
	-}

printable :: String
printable = ['0' .. '9'] ++ ['a' .. 'z'] ++ ['A' .. 'Z'] ++ symbols ++ " "

symbols :: String
symbols = "$+<=>^`|~!\"#%&'()*,-./:;?@[\\]_{}"

putEscChar :: Int -> Char -> IO ()
putEscChar clr c
	| c `elem` printable = do
		putStr ("\x1b[1m\x1b[" ++ show clr ++ "m")
		putChar c
		putStr "\x1b[39m\x1b[0m"
	| otherwise = do
		putStr ("\x1b[" ++ show clr ++ "m")
		putStr (toTwo (showHex (ord c) ""))
		putStr "\x1b[39m"

toTwo :: String -> String
toTwo n = replicate (2 - length n) '0' ++ n

mkClientHello :: Random -> Content
mkClientHello r = ContentHandshake (Version 3 3) . (: []) . HandshakeClientHello $
	ClientHello (ProtocolVersion 3 3) r (SessionId "")
	[TLS_RSA_WITH_AES_128_CBC_SHA] [CompressionMethodNull] Nothing

(+++) :: BS.ByteString -> BS.ByteString -> BS.ByteString
(+++) = BS.append

appDataGet :: Content
appDataGet = ContentApplicationData (Version 3 3) $
	"GET / HTTP/1.1\r\n" +++
	"Host: localhost:4492\r\n" +++
	"User-Agent: Mozilla/5.0 (X11; Linux i686; rv:24.0) " +++
		"Gecko/20140415 Firefox/24.0\r\n" +++
	"Accept: text/html,application/xhtml+xml,"+++
		"application/xml;q=0.9,*/*;q=0.8\r\n" +++
	"Accept-Language: ja,en-us;q-0.7,en;q=0.3\r\n" +++
	"Accept-Encoding: gzip, deflate\r\n" +++
	"Connection: keep-alive\r\n" +++
	"Cache-Control: max-age=0\r\n\r\n"
