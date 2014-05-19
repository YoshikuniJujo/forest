{-# LANGUAGE PackageImports, OverloadedStrings #-}

module Main (main) where

import Control.Monad.IO.Class

import Control.Applicative
import Control.Monad
import Control.Concurrent
import System.Environment
import System.IO
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
import qualified Crypto.PubKey.RSA.Prim as RSA

import System.Console.GetOpt

options :: [OptDescr Option]
options = [
	Option "d" ["disable-client-cert"] (NoArg OptDisableClientCert)
		"disable client certification" ]

data Option
	= OptDisableClientCert
	deriving (Show, Eq)

main :: IO ()
main = do
	cidRef <- newIORef 0
	certChain <- CertificateChain <$> readSignedObject "localhost.crt"
	[PrivKeyRSA pk] <- readKeyFile "localhost.key"
	certStore <- makeCertificateStore <$> readSignedObject "cacert.pem"
--	[PrivKeyRSA pkys] <- readKeyFile "yoshikuni.key"
	(opts, args, _errs) <- getOpt Permute options <$> getArgs
	let doClientCert = OptDisableClientCert `notElem` opts
	[pcl] <- mapM ((PortNumber . fromInt <$>) . readIO) args
	scl <- listenOn pcl
	forever $ do
		cid <- readIORef cidRef
		modifyIORef cidRef succ
		client <- fst3 <$> accept scl
		_ <- forkIO $ do
			ep <- createEntropyPool
			run' doClientCert certStore certChain cid pk client
			{-
			(\act -> evalTlsIo act ep client pk) $
				run doClientCert certStore certChain cid
				-}
		return ()
			
run :: Bool -> CertificateStore -> CertificateChain -> Int -> TlsIo Content ()
run dcc certStore certChain cid =
	handshake dcc certStore certChain cid >> content cid

run' :: Bool -> CertificateStore -> CertificateChain -> Int ->
	PrivateKey -> Handle -> IO ()
run' dcc certStore certChain cid pk cl = do
	tls <- runOpen (handshake dcc certStore certChain cid) pk cl
	tGetWhole tls >>= print
	tPut tls answer

handshake :: Bool -> CertificateStore -> CertificateChain -> Int -> TlsIo Content ()
handshake dcc certStore certChain cid = do

	------------------------------------------
	--           CLIENT HELLO               --
	------------------------------------------
	ch <- readContent
	maybe (throwError "No Client Hello") setClientRandom $ clientRandom ch
	output Client cid "Hello" [
		take 60 (show ch) ++ "...",
		maybe "No Version" show $ clientVersion ch ]

	------------------------------------------
	--           SERVER HELLO               --
	------------------------------------------
	sr <- Random <$> randomByteString 32
	writeContentList $ [
		serverHello sr,
		certificate certChain ] ++ if not dcc then [] else [
			certificateRequest $ getDistinguishedNames certStore ]
	writeContent serverHelloDone
	setVersion version
	setServerRandom sr
	cacheCipherSuite cipherSuite
	output Server cid "Hello" [show version, show cipherSuite]

	------------------------------------------
	--          CLIENT CERTIFICATION        --
	------------------------------------------
	pub <- if not dcc then return Nothing else
		Just <$> clientCertification cid certStore

	------------------------------------------
	--          CLIENT KEY EXCHANGE         --
	------------------------------------------
	c2 <- readContent
	let	Just (EncryptedPreMasterSecret epms) = encryptedPreMasterSecret c2
	pms <- decryptRSA epms
	generateKeys pms
	output Client cid "Key Exchange" [take 60 (show c2) ++ " ..."]

	------------------------------------------
	--          CERTIFICATE VERIFY          --
	------------------------------------------
	maybe (return ()) (certificateVerify cid) pub

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
	writeFragment $ contentToFragment changeCipherSpec
	flushCipherSuite Server
	output Server cid "Change Cipher Spec" [show changeCipherSpec]

	------------------------------------------
	--      SERVER FINISHED                 --
	------------------------------------------
	sf <- finishedHash Server
	writeFragment . contentToFragment $ finished sf
	output Server cid "Finished" [showHandshake $ finished sf]

content :: Int -> TlsIo Content ()
content cid = do

	------------------------------------------
	--      CLIENT GET                      --
	------------------------------------------
	g <- readContent
--	output Client cid "GET" [take 60 (show g) ++ "..."]
	output Client cid "GET" [show g]

	------------------------------------------
	--      SERVER CONTENT                  --
	------------------------------------------
	writeContent $ applicationData answer
	output Server cid "Contents"
		[take 60 (show $ applicationData answer) ++ "..."]

clientCertification :: Int -> CertificateStore -> TlsIo Content PublicKey
clientCertification cid certStore = do
	------------------------------------------
	--          CLIENT CERTIFICATION        --
	------------------------------------------
	c1 <- readContent
	let	Just cc@(CertificateChain certs) = certificateChain c1
	let 	PubKeyRSA pub = certPubKey .  getCertificate $ head certs
	v <- liftIO $ validateDefault certStore
		(ValidationCache query add) ("Yoshikuni", "Yoshio") cc
	output Client cid "Client Certificate" [
		take 60 (show c1) ++ " ...",
		if null v then "Validate Success" else "Validate Failure" ]
	return pub

certificateVerify :: Int -> PublicKey -> TlsIo Content ()
certificateVerify cid pub = do
	------------------------------------------
	--          CERTIFICATE VERIFY          --
	------------------------------------------
	hash <- clientVerifyHash pub
	c3 <- readContentNoHash
	let	Just ds = digitalSign c3
		encHash = RSA.ep pub ds
	unless (hash == encHash) $
		throwError "client authentification failed"
	fragmentUpdateHash $ contentToFragment c3
	output Client cid "Certificate Verify" [
			take 60 (show c3) ++ " ...",
			"local hash   : \"..." ++ drop 410 (show hash),
			"recieved hash: \"..." ++ drop 410 (show encHash) ]

readContentNoHash :: TlsIo Content Content
readContentNoHash = do
	c <- readCached readContentList
		<* updateSequenceNumber Client
	return c

readContent :: TlsIo Content Content
readContent = do
	c <- readCached readContentList
		<* updateSequenceNumber Client
	fragmentUpdateHash $ contentToFragment c
	return c

readContentList :: TlsIo Content [Content]
readContentList = (\(Right c) -> c) .  fragmentToContent <$> readFragmentNoHash

writeContentList :: [Content] -> TlsIo Content ()
writeContentList cs = do
	let f = contentListToFragment cs
	updateSequenceNumber Client
	writeFragment f
	fragmentUpdateHash f

writeContent :: Content -> TlsIo Content ()
writeContent c = do
	let f = contentToFragment c
	writeFragment f
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
	"003\r\n",
	"abc\r\n",
	"0\r\n\r\n"
 ]

query :: ValidationCacheQueryCallback
query _ _ _ = return ValidationCacheUnknown

add :: ValidationCacheAddCallback
add _ _ _ = return ()

output :: Partner -> Int -> String -> [String] -> TlsIo Content ()
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
