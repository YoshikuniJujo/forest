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

mkhs :: Handshake -> Content
mkhs = ContentHandshake version

openClient :: Handle -> RSA.PrivateKey ->
	CertificateChain -> Maybe (String, CertificateStore) -> IO TlsClient
openClient cl pk = (runOpen cl pk .) . handshake

handshake :: CertificateChain -> Maybe (String, CertificateStore) -> TlsIo Content ()
handshake cc mcs = do
	cv <- clientHello
	serverHello cc $ snd <$> mcs
	mpub <- maybe (return Nothing) ((Just <$>) . uncurry clientCertificate) mcs
	clientKeyExchange cv
	maybe (return ()) certificateVerify mpub
	clientChangeCipherSuite
	clientFinished
	serverChangeCipherSuite
	serverFinished

clientHello :: TlsIo Content Version
clientHello = do
	hs <- readHandshake $ \(Version mj _) -> mj == 3
	case hs of
		HandshakeClientHello ch@(ClientHello vsn rnd _ _ _ _) ->
			setClientRandom rnd >> err ch >> return vsn
		_ -> throwError "Not Client Hello"
	where
	err (ClientHello vsn _ _ css cms _)
		| vsn < version = throwError emCVersion
		| TLS_RSA_WITH_AES_128_CBC_SHA `notElem` css = throwError emCSuite
		| CompressionMethodNull `notElem` cms = throwError emCMethod
		| otherwise = return ()
	err _ = throwError "Never occur"

emCVersion, emCSuite, emCMethod :: String
emCVersion = "Client Version should 3.3 or more"
emCSuite = "No supported Cipher Suites"
emCMethod = "No supported Compression Method"

serverHello :: CertificateChain -> Maybe CertificateStore -> TlsIo Content ()
serverHello cc mcs = do
	sr <- Random <$> randomByteString 32
	setVersion version
	setServerRandom sr
	cacheCipherSuite TLS_RSA_WITH_AES_128_CBC_SHA
	writeContentList $ [mksh sr, cert] ++ maybe [] ((: []) . certReq) mcs
		++ [ContentHandshake version HandshakeServerHelloDone]
	where
	mksh sr = mkhs . HandshakeServerHello $ ServerHello version sr
		(SessionId "")
		TLS_RSA_WITH_AES_128_CBC_SHA
		CompressionMethodNull Nothing
	certReq = mkhs . HandshakeCertificateRequest
		. CertificateRequest
			[ClientCertificateTypeRsaSign]
			[(HashAlgorithmSha256, SignatureAlgorithmRsa)]
		. getDistinguishedNames
	cert = mkhs $ HandshakeCertificate cc

clientCertificate ::
	HostName -> CertificateStore -> TlsIo Content RSA.PublicKey
clientCertificate hn cs = do
	hs <- readHandshake (== version)
	case hs of
		HandshakeCertificate cc@(CertificateChain (c : _)) -> do
			case certPubKey $ getCertificate c of
				PubKeyRSA pub -> chk cc >> return pub
				p -> throwError $ "Not implemented: " ++ show p
		_ -> throwError "Not Certificate"
	where
	vc = ValidationCache
		(\_ _ _ -> return ValidationCacheUnknown) (\_ _ _ -> return ())
	chk cc = do
		v <- liftIO $ validateDefault cs vc (hn, "") cc
		unless (null v) . throwError $ "Validate Failure: " ++ show v

clientKeyExchange :: Version -> TlsIo Content ()
clientKeyExchange (Version cvmjr cvmnr) = do
	hs <- readHandshake (== version)
	case hs of
		HandshakeClientKeyExchange (EncryptedPreMasterSecret epms) -> do
			r <- randomByteString 46
			pms <- mkpms epms `catchError` const (return $ dummy r)
			generateKeys pms
		_ -> throwError "Not Client Key Exchange"
	where
	dummy r = cvmjr `BS.cons` cvmnr `BS.cons` r
	mkpms epms = do
		pms <- decryptRSA epms
		case BS.uncons pms of
			Just (pmsvmjr, pmstail) -> case BS.uncons pmstail of
				Just (pmsvmnr, _) -> do
					unless (pmsvmjr == cvmjr &&
						pmsvmnr == cvmnr) $
						throwError "bad: version"
					unless (BS.length pms == 48) $
						throwError "bad: length"
					return pms
				_ -> throwError "bad length"
			_ -> throwError "bad length"

-- refactoring --

certificateVerify :: RSA.PublicKey -> TlsIo Content ()
certificateVerify pub = do
	hash <- clientVerifyHash pub
	c3 <- readContentNoHash
	let	Just ds = digitalSign c3
		encHash = RSA.ep pub ds
	unless (hash == encHash) $
		throwError "client authentification failed"
	fragmentUpdateHash $ contentToFragment c3
	output 0 "Client Certificate Verify" [
			"local hash   : \"..." ++ drop 410 (show hash),
			"recieved hash: \"..." ++ drop 410 (show encHash) ]

clientChangeCipherSuite :: TlsIo Content ()
clientChangeCipherSuite = do
	cccs <- readContent
	when (doesChangeCipherSpec cccs) $ flushCipherSuite Client

serverChangeCipherSuite :: TlsIo Content ()
serverChangeCipherSuite = do
	writeFragment $ contentToFragment changeCipherSpec
	flushCipherSuite Server

serverFinished :: TlsIo Content ()
serverFinished = do
	sf <- finishedHash Server
	writeFragment . contentToFragment $ finished sf

readHandshake :: (Version -> Bool) -> TlsIo Content Handshake
readHandshake ck = do
	cnt <- readContent
	case cnt of
		ContentHandshake v hs
			| ck v -> return hs
			| otherwise -> throwError "Not supported layer version"
		_ -> throwError "Not Handshake"

clientFinished :: TlsIo Content ()
clientFinished = do
	fhc <- finishedHash Client
	cf <- readContent
	output 0 "Client Finished" [show fhc, showHandshake cf]

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

{-
writeContent :: Content -> TlsIo Content ()
writeContent c = do
	let f = contentToFragment c
	writeFragment f
	fragmentUpdateHash f
	-}

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

readCertificateChain :: FilePath -> IO CertificateChain
readCertificateChain = (CertificateChain <$>) . readSignedObject

readRsaKey :: FilePath -> IO RSA.PrivateKey
readRsaKey fp = do [PrivKeyRSA pk] <- readKeyFile fp; return pk

readCertificateStore :: [FilePath] -> IO CertificateStore
readCertificateStore fps =
	makeCertificateStore . concat <$> mapM readSignedObject fps
