{-# LANGUAGE OverloadedStrings, ScopedTypeVariables #-}

module TlsClient (
	TlsServer,
	openTlsServer, tPut, tGetByte, tGetLine, tGet, tGetContent, tClose,

	Option(..),
	tPutWithCT,
	Content(..),
	ContentType(..),
	Handshake(..),
	Version(..),
) where

import System.IO
import Control.Applicative
import Control.Monad
import Data.List
import Data.Word
import qualified Data.ByteString as BS
import Data.X509
import Data.X509.CertificateStore
import Data.X509.Validation
import qualified Crypto.PubKey.RSA as RSA

import Fragment
import Content
import Basic

import Crypto.PubKey.DH

import Data.Ratio

openTlsServer :: [(RSA.PrivateKey, CertificateChain)] -> CertificateStore -> Handle
	-> [Option] -> IO TlsServer
openTlsServer ccs certStore sv opts = runOpen (handshake ccs certStore opts) sv

isIncluded :: (RSA.PrivateKey, CertificateChain) -> [DistinguishedName] -> Bool
isIncluded (_, CertificateChain certs) dns = let
	idn = certIssuerDN . signedObject . getSigned $ last certs in
	idn `elem` dns

helloVersionFromOptions :: [Option] -> (Word8, Word8)
helloVersionFromOptions =
	maybe (3, 3) (\(OptHelloVersion mjr mnr) -> (mjr, mnr)) .
		find isOptHelloVersion

clientVersionFromOptions :: [Option] -> (Word8, Word8)
clientVersionFromOptions =
	maybe (3, 3) (\(OptClientVersion mjr mnr) -> (mjr, mnr)) .
		find isOptClientVersion

handshake :: [(RSA.PrivateKey, CertificateChain)] -> CertificateStore
	-> [Option] -> TlsIo Content ()
handshake ccs certStore opts = do

	-------------------------------------------
	--     CLIENT HELLO                      --
	-------------------------------------------
	cr <- Random <$> randomByteString 32
	let ch = clientHello cr
		(helloVersionFromOptions opts)
		(clientVersionFromOptions opts)
		(if OptEmptyCipherSuite `elem` opts then [] else [
			TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
			TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
			TLS_RSA_WITH_AES_128_CBC_SHA256,
			TLS_RSA_WITH_AES_128_CBC_SHA])
		(if OptEmptyCompressionMethod `elem` opts
			then []
			else [CompressionMethodNull])
	case (OptStartByChangeCipherSpec `elem` opts,
		OptStartByFinished `elem` opts) of
		(True, _) -> writeContent changeCipherSpec
		(_, True) -> writeContent $ ContentHandshake version $
			HandshakeFinished ""
		_ -> writeContent ch
	fragmentUpdateHash $ contentToFragment ch
	maybe (throwError "No Client Hello") setClientRandom $ clientRandom ch

	-------------------------------------------
	--     SERVER HELLO                      --
	-------------------------------------------
	sh <- readContent
	liftIO $ print sh
	maybe (throwError "No Server Hello") setVersion $ serverVersion sh
	maybe (throwError "No Server Hello") setServerRandom $
		serverRandom sh
	maybe (throwError "No Server Hello") cacheCipherSuite $
		serverCipherSuite sh
	liftIO . putStrLn $ "SERVER HELLO: " ++ take 60 (show sh) ++ "..."

	-------------------------------------------
	--     SERVER CERTIFICATE                --
	-------------------------------------------
	crt <- readContent
	let	Just scc@(CertificateChain (cert : _)) = certificateChain crt
		PubKeyRSA pub = certPubKey $ getCertificate cert
	v <- liftIO $ validateDefault certStore
		(ValidationCache query add) ("localhost", "localhost da") scc
	liftIO . putStrLn $ "VALIDATE RESULT: " ++ show v
	unless (null v) $ throwError "SERVER VALIDATION FAILURE"
	liftIO . putStrLn $ "CERTIFICATE: " ++ take 60 (show crt) ++ "..."
	liftIO . putStrLn $ "CERTIFICATE Chain: " ++ take 60 (show scc) ++ "..."
	liftIO . putStrLn $ "PUBKEY: " ++ take 60 (show pub) ++ "..."

	-------------------------------------------
	--     CERTIFICATE REQUEST               --
	-------------------------------------------
	-------------------------------------------
	--     SERVER HELLO DONE                 --
	-------------------------------------------
	(crtReq, yc, dhsk) <- serverHelloDone pub

	let	Just (CertificateRequest _ _ sdn) = crtReq
		(pk, cc) = head $ filter (`isIncluded` sdn) ccs

	-------------------------------------------
	--     CLIENT CERTIFICATE                --
	-------------------------------------------
	case crtReq of
		Just _ -> do
			writeContent $ if OptNotClientCertificate `elem` opts
				then ContentHandshake version $
					HandshakeFinished ""
				else certificate cc
			fragmentUpdateHash . contentToFragment $ certificate cc
		_ -> return ()

	-------------------------------------------
	--     CLIENT KEY EXCHANGE               --
	-------------------------------------------
--	let pmsVer = if OptPmsVerErr `elem` opts then "\x99\x99" else "\x03\x03"
--	pms <- (pmsVer `BS.append`) <$> randomByteString 46
--	epms' <- encryptRSA pub pms
--	liftIO $ putStrLn $ "Encrypted Pre Master Secret: " ++ show epms'
	generateKeys dhsk -- pms
--	let	cke'' = makeClientKeyExchange $ EncryptedPreMasterSecret epms'
	let	cke'' = makeClientKeyExchange $ EncryptedPreMasterSecret yc
	writeContent $ if OptNotClientKeyExchange `elem` opts
		then ContentHandshake version $ HandshakeFinished ""
		else cke''
	fragmentUpdateHash $ contentToFragment cke''
--	liftIO $ putStrLn $ "KEY EXCHANGE: " ++ show (contentToFragment cke'')
	liftIO $ putStrLn "GENERATE KEYS"

--	debugPrintKeys

	-------------------------------------------
	--     CERTIFICATE VERIFY                --
	-------------------------------------------
	case crtReq of
		Just _ -> do
			signed <- clientVerifySign pk $ OptBadSignature `elem` opts
			let	(ha, sa) = if OptNotExistHashAndSignature `elem` opts
					then (HashAlgorithmRaw 255,
						SignatureAlgorithmRaw 255)
					else (HashAlgorithmSha256,
						SignatureAlgorithmRsa)
				cv = if OptNotCertificateVerify `elem` opts
					then ContentHandshake version $
						HandshakeFinished ""
					else makeVerify ha sa signed
			writeContent cv
			fragmentUpdateHash . contentToFragment $ cv
		_ -> return ()

	-------------------------------------------
	--     CLIENT CHANGE CIPHER SPEC         --
	-------------------------------------------
	writeContent changeCipherSpec
	fragmentUpdateHash $ contentToFragment changeCipherSpec
	flushCipherSuite Client

	-------------------------------------------
	--     CLIENT FINISHED                   --
	-------------------------------------------
	fhc <- finishedHash Client
	liftIO . putStrLn $ "CLIENT FINISHED: " ++ show fhc
	writeContent $ finished fhc
	fragmentUpdateHash . contentToFragment $ finished fhc

	liftIO $ putStrLn "CLIENT FINISHED DONE"

	-------------------------------------------
	--     SERVER CHANGE CIPHER SPEC         --
	-------------------------------------------
	sccs <- readContent
	when (doesChangeCipherSpec sccs) $ flushCipherSuite Server
	liftIO $ print sccs
	when (isFatal sccs) . error $ show sccs
	liftIO . putStrLn $ "SERVER CHANGE CIPHER SPEC: " ++ take 60 (show sccs)

	-------------------------------------------
	--     SERVER FINISHED                   --
	-------------------------------------------
	sfhc <- finishedHash Server
	scf <- readContent
	updateSequenceNumberSmart Server
	sfinish <- maybe (throwError $ "Not Finished: " ++ show scf)
		return $ getFinish scf
	liftIO $ do
		putStrLn $ "SERVER FINISHED FIREFOX     : " ++ take 60 (show sfinish)
		putStrLn $ "SERVER FINISHED CALCULATE   : " ++ take 60 (show sfhc)

serverHelloDone :: RSA.PublicKey -> TlsIo Content (Maybe CertificateRequest, BS.ByteString, BS.ByteString)
serverHelloDone pub = do

	-------------------------------------------
	--     CERTIFICATE REQUEST               --
	-------------------------------------------
	cske <- readContent
	liftIO . putStrLn $
--		"CERTIFICATE REQUEST: " ++ take 60 (show crtReq) ++ "..."
		"CERTIFICATE REQUEST: " ++ show cske

	let	ContentHandshake _ (HandshakeServerKeyExchange ske) = cske
		ServerKeyExchange ps ys _ _ _ _ = ske

	cr <- getClientRandom
	sr <- getServerRandom
	liftIO . print $ verifyServerKeyExchange pub cr sr ske

	g <- getRandomGen
	let	(pr, g') = generatePrivate g ps
		dhsk = getShared ps pr ys
	setRandomGen g'
	liftIO . putStrLn $ "PRIVATE NUMBER: " ++ show pr
	liftIO . putStrLn $ "SHARED KEY    : " ++ show dhsk

	crtReq <- readContent

	unless (doesServerHelloDone crtReq) $ do

	-------------------------------------------
	--     SERVER HELLO DONE                 --
	-------------------------------------------
		shd <- readContent
		liftIO . putStrLn $ "SERVER HELLO DONE: " ++ take 60 (show shd) ++ "..."

	return $ (getCertificateRequest crtReq,
		integerToByteString $ toInteger $ calculatePublic ps pr,
--		integerToByteString $ toInteger (calculatePublic ps pr) + 1,
		integerToByteString $ numerator $ toRational dhsk)

readContent :: TlsIo Content Content
readContent = do
	c <- readCached readContentList
	fragmentUpdateHash $ contentToFragment c
	return c

readContentList :: TlsIo Content [Content]
readContentList = (\ec -> case ec of
		Right c -> c;
		Left err -> error $ "readContentList: " ++ err) .
	fragmentToContent <$> readFragment

_writeContentList :: Partner -> [Content] -> TlsIo Content ()
_writeContentList partner cs = do
	let f = contentListToFragment cs
	updateSequenceNumberSmart partner
	writeFragment f

writeContent :: Content -> TlsIo Content ()
writeContent c = do
	let f = contentToFragment c
	writeFragment f

query :: ValidationCacheQueryCallback
query _ _ _ = return ValidationCacheUnknown

add :: ValidationCacheAddCallback
add _ _ _ = return ()
