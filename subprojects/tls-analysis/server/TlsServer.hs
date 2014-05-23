{-# LANGUAGE OverloadedStrings #-}

module TlsServer (
	TlsClient, openClient,
	readRsaKey, readCertificateChain, readCertificateStore) where

import Control.Applicative
import Control.Monad
import Control.Monad.IO.Class
import Control.Concurrent
import Data.Word
import qualified Data.ByteString as BS
import Data.X509
import Data.X509.File
import Data.X509.Validation
import Data.X509.CertificateStore
import System.IO
import System.IO.Unsafe
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA

import Fragment
import Content

readCertificateChain :: FilePath -> IO CertificateChain
readCertificateChain = (CertificateChain <$>) . readSignedObject

readRsaKey :: FilePath -> IO RSA.PrivateKey
readRsaKey fp = do [PrivKeyRSA pk] <- readKeyFile fp; return pk

readCertificateStore :: [FilePath] -> IO CertificateStore
readCertificateStore fps =
	makeCertificateStore . concat <$> mapM readSignedObject fps

data Option
	= OptDisableClientCert
	deriving (Show, Eq)

openClient :: Handle ->
	RSA.PrivateKey -> CertificateChain -> Maybe CertificateStore -> IO TlsClient
openClient cl pk cc mcs = case mcs of
	Just cs -> openTlsClient_ True cs cc pk cl
	_ -> openTlsClient_ False undefined cc pk cl

openTlsClient_ :: Bool -> CertificateStore -> CertificateChain -> RSA.PrivateKey ->
	Handle -> IO TlsClient
openTlsClient_ dcc certStore certChain =
	runOpen (handshake dcc certStore certChain 0)

handshake :: Bool -> CertificateStore -> CertificateChain -> Int -> TlsIo Content ()
handshake dcc certStore certChain cid = do

	------------------------------------------
	--           CLIENT HELLO               --
	------------------------------------------
	ch <- readContent
	maybe (throwError "No Client Hello") setClientRandom $ clientRandom ch
	let Just (Version cvmjr cvmnr) = clientVersion ch
--	liftIO . putStrLn $ "CLIENT VERSION: " ++ show cvmjr ++ " " ++ show cvmnr
	output Client cid "Hello" [maybe "No Version" show $ clientVersion ch]

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
	r <- randomByteString 46
	pms <- makePms cvmjr cvmnr epms `catchError` const (return .
		BS.cons cvmjr $ BS.cons cvmnr r)
--	liftIO . putStrLn $ "Pre Master Secret: " ++ show pms
	generateKeys pms
	output Client cid "Key Exchange" []

	------------------------------------------
	--          CERTIFICATE VERIFY          --
	------------------------------------------
	maybe (return ()) (certificateVerify cid) pub

	------------------------------------------
	--      CLIENT CHANGE CIPHER SPEC       --
	------------------------------------------
	cccs <- readContent
	when (doesChangeCipherSpec cccs) $ flushCipherSuite Client
	output Client cid "Change Cipher Spec" []

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
	output Server cid "Change Cipher Spec" []

	------------------------------------------
	--      SERVER FINISHED                 --
	------------------------------------------
	sf <- finishedHash Server
	writeFragment . contentToFragment $ finished sf
	output Server cid "Finished" [showHandshake $ finished sf]

clientCertification :: Int -> CertificateStore -> TlsIo Content RSA.PublicKey
clientCertification cid certStore = do
	------------------------------------------
	--          CLIENT CERTIFICATION        --
	------------------------------------------
	c1 <- readContent
	let	Just cc@(CertificateChain certs) = certificateChain c1
	let 	PubKeyRSA pub = certPubKey .  getCertificate $ head certs
	v <- liftIO $ validateDefault certStore
		(ValidationCache query add) ("Yoshikuni", "Yoshio") cc
	output Client cid "Client Certificate"
		[if null v then "Validate Success" else "Validate Failure"]
	return pub

certificateVerify :: Int -> RSA.PublicKey -> TlsIo Content ()
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
--			take 60 (show c3) ++ " ...",
			"local hash   : \"..." ++ drop 410 (show hash),
			"recieved hash: \"..." ++ drop 410 (show encHash) ]

readContentNoHash :: TlsIo Content Content
readContentNoHash = readCached readContentList <* updateSequenceNumber Client

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
	end = liftIO $ writeChan locker ()

locker :: Chan ()
locker = unsafePerformIO $ ((>>) <$> (`writeChan` ()) <*> return) =<< newChan

getDistinguishedNames :: CertificateStore -> [DistinguishedName]
getDistinguishedNames cs =
	map (certIssuerDN .  signedObject . getSigned) $ listCertificates cs

makePms :: Word8 -> Word8 -> BS.ByteString -> TlsIo Content BS.ByteString
makePms cvmjr cvmnr epms = do
	pms <- decryptRSA epms
	let	Just (pmsvmjr, pmstail) = BS.uncons pms
		Just (pmsvmnr, _) = BS.uncons pmstail
	unless (pmsvmjr == cvmjr && pmsvmnr == cvmnr) $ throwError "bad: version"
	unless (BS.length pms == 48) $ throwError "bad: length"
	return pms
