{-# LANGUAGE OverloadedStrings #-}

module TlsServer (
	TlsClient, openClient,
	readRsaKey, readCertificateChain, readCertificateStore) where

import Control.Applicative
import Control.Monad
import Control.Monad.IO.Class
import Control.Concurrent
import qualified Data.ByteString as BS
import Data.X509
import Data.X509.File
import Data.X509.Validation
import Data.X509.CertificateStore
import System.IO
import System.IO.Unsafe
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.Prim as RSA

import Content
import Fragment

version :: Version
version = Version 3 3

openClient :: Handle -> RSA.PrivateKey ->
	CertificateChain -> Maybe CertificateStore -> IO TlsClient
openClient cl pk cc mcs = runOpen (handshake cc mcs) pk cl

handshake :: CertificateChain -> Maybe CertificateStore -> TlsIo Content ()
handshake cc mcs = do
	cv <- clientHello
	serverHello cc mcs
	pub <- maybe (return Nothing) ((Just <$>) . clientCertification) mcs
	clientKeyExchange cv
	maybe (return ()) certificateVerify pub
	cccs <- readContent
	when (doesChangeCipherSpec cccs) $ flushCipherSuite Client
	clientFinished
	writeFragment $ contentToFragment changeCipherSpec
	flushCipherSuite Server
	sf <- finishedHash Server
	writeFragment . contentToFragment $ finished sf

clientHello :: TlsIo Content Version
clientHello = do
	cnt <- readContent
	case cnt of
		ContentHandshake (Version 3 _) (HandshakeClientHello
			(ClientHello vsn rnd _sid css cms _mex)) -> do
			setClientRandom rnd
			unless (vsn >= version) $
				throwError "Client Version should 3.3 or more"
			unless (TLS_RSA_WITH_AES_128_CBC_SHA `elem` css) $
				throwError "No Supported Cipher Suites"
			unless (CompressionMethodNull `elem` cms) $
				throwError "No Supported Compression Method"
			return vsn
		ContentHandshake _ (HandshakeClientHello _) ->
			throwError "Bad record layer version"
		_ -> throwError "Not Client Hello"

serverHello :: CertificateChain -> Maybe CertificateStore -> TlsIo Content ()
serverHello cc mcs = do
	sr <- Random <$> randomByteString 32
	setVersion version
	setServerRandom sr
	cacheCipherSuite TLS_RSA_WITH_AES_128_CBC_SHA
	writeContentList $ [mksh sr, certificate cc] ++ crtreq ++ [serverHelloDone]
	where
	mksh sr = ContentHandshake version . HandshakeServerHello $ ServerHello
		version sr (SessionId "") TLS_RSA_WITH_AES_128_CBC_SHA
		CompressionMethodNull Nothing
	crtreq = case mcs of
		Just cs -> [certificateRequest $ getDistinguishedNames cs]
		_ -> []

readHandshake :: TlsIo Content Handshake
readHandshake = do
	cnt <- readContent
	case cnt of
		ContentHandshake v hs
			| v == version -> return hs
			| otherwise -> throwError "Not supported layer version"
		_ -> throwError "Not Handshake"

clientKeyExchange :: Version -> TlsIo Content ()
clientKeyExchange cv = do
	Just (EncryptedPreMasterSecret epms) <-
		encryptedPreMasterSecret <$> readContent
	r <- randomByteString 46
	pms <- makePms cv epms `catchError` const
		(return $ versionToByteString cv `BS.append` r)
	generateKeys pms

clientFinished :: TlsIo Content ()
clientFinished = do
	fhc <- finishedHash Client
	cf <- readContent
	output 0 "Client Finished" [show fhc, showHandshake cf]

clientCertification :: CertificateStore -> TlsIo Content RSA.PublicKey
clientCertification certStore = do
	------------------------------------------
	--          CLIENT CERTIFICATION        --
	------------------------------------------
	c1 <- readContent
	let	Just cc@(CertificateChain certs) = certificateChain c1
	let 	PubKeyRSA pub = certPubKey .  getCertificate $ head certs
	v <- liftIO $ validateDefault certStore
		(ValidationCache query add) ("Yoshikuni", "Yoshio") cc
	output 0 "Client Certificate"
		[if null v then "Validate Success" else "Validate Failure"]
	return pub

certificateVerify :: RSA.PublicKey -> TlsIo Content ()
certificateVerify pub = do
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
	output 0 "Client Certificate Verify" [
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

output :: Int -> String -> [String] -> TlsIo Content ()
output cid msg strs = do
	begin
	liftIO . mapM_ putStr $ map (unlines . map ("\t" ++) . lines) strs
	end
	where
	begin = liftIO $ do
		readChan locker
		putStrLn $ replicate 10 '-' ++ " (" ++
			show cid ++ ") " ++ msg ++ " " ++ replicate 10 '-'
	end = liftIO $ writeChan locker ()

locker :: Chan ()
locker = unsafePerformIO $ ((>>) <$> (`writeChan` ()) <*> return) =<< newChan

getDistinguishedNames :: CertificateStore -> [DistinguishedName]
getDistinguishedNames cs =
	map (certIssuerDN .  signedObject . getSigned) $ listCertificates cs

makePms :: Version -> BS.ByteString -> TlsIo Content BS.ByteString
makePms (Version cvmjr cvmnr) epms = do
	pms <- decryptRSA epms
	let	Just (pmsvmjr, pmstail) = BS.uncons pms
		Just (pmsvmnr, _) = BS.uncons pmstail
	unless (pmsvmjr == cvmjr && pmsvmnr == cvmnr) $ throwError "bad: version"
	unless (BS.length pms == 48) $ throwError "bad: length"
	return pms

readCertificateChain :: FilePath -> IO CertificateChain
readCertificateChain = (CertificateChain <$>) . readSignedObject

readRsaKey :: FilePath -> IO RSA.PrivateKey
readRsaKey fp = do [PrivKeyRSA pk] <- readKeyFile fp; return pk

readCertificateStore :: [FilePath] -> IO CertificateStore
readCertificateStore fps =
	makeCertificateStore . concat <$> mapM readSignedObject fps
