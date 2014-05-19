{-# LANGUAGE PackageImports, OverloadedStrings #-}

module Server (
	TlsClient, openTlsClient, tPut, tGet, tGetLine, tGetByte, tGetContent,
) where

import Control.Monad.IO.Class

import Control.Applicative
import Control.Monad
import Control.Concurrent
import System.IO
import System.IO.Unsafe
import Data.X509

import Fragment
import Content
import Basic

import Data.X509.CertificateStore
import Data.X509.Validation

import Crypto.PubKey.RSA
import qualified Crypto.PubKey.RSA.Prim as RSA

data Option
	= OptDisableClientCert
	deriving (Show, Eq)

openTlsClient :: Bool -> CertificateStore -> CertificateChain -> PrivateKey ->
	Handle -> IO TlsClient
openTlsClient dcc certStore certChain pk cl =
	runOpen (handshake dcc certStore certChain 0) pk cl
	
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
