{-# LANGUAGE OverloadedStrings, ScopedTypeVariables #-}

module CommandLine (readCommandLine) where

import Control.Applicative ((<$>), (<*>))
import Control.Monad (unless)
import Data.List (find)
import System.Console.GetOpt (getOpt, ArgOrder(..), OptDescr(..), ArgDescr(..))
import System.Exit (exitFailure)
import Network (PortID(..))
import ReadFile (
	readRsaKey, readEcPrivKey, readCertificateChain, readCertificateStore)
import CipherSuite (CipherSuite(..), CipherSuiteKeyEx(..), CipherSuiteMsgEnc(..))

import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA

ecdsaKeyFile, ecdsaCertFile :: String
ecdsaKeyFile = "localhost_ecdsa.key"
ecdsaCertFile = "localhost_ecdsa.cert"

readCommandLine :: [String] -> IO (
	PortID,
	[CipherSuite],
	FilePath,
	(RSA.PrivateKey, X509.CertificateChain),
	(ECDSA.PrivateKey, X509.CertificateChain),
	Maybe X509.CertificateStore )
readCommandLine args = do
	let	(opts, _, errs) = getOpt Permute options args
		css = optsToCipherSuites opts
	unless (null errs) $ mapM_ putStr errs >> exitFailure
	let	port = optsToPort opts
		kfp = optsToKeyFile opts
		cfp = optsToCertFile opts
		tstd = optsToTestDirectory opts
	rsa <- (,) <$> readRsaKey kfp <*> readCertificateChain cfp
	ec <- (,) <$> readEcPrivKey ecdsaKeyFile
		<*> readCertificateChain ecdsaCertFile
	mcs <- if OptDisableClientCert `elem` opts
		then return Nothing
		else Just <$> readCertificateStore ["cacert.pem"]
	return (port, css, tstd, rsa, ec, mcs)

data Option
	= OptPort PortID
	| OptKeyFile FilePath
	| OptCertFile FilePath
	| OptDisableClientCert
	| OptLevel CipherSuiteLevel
	| OptTestDirectory FilePath
	deriving (Show, Eq)

data CipherSuiteLevel
	= ToEcdsa256 | ToEcdsa | ToEcdhe256 | ToEcdhe
	| ToDhe256   | ToDhe   | ToRsa256   | ToRsa
	| NoLevel
	deriving (Show, Eq, Enum)

options :: [OptDescr Option]
options = [
	Option "p" ["port"]
		(ReqArg (OptPort . PortNumber . fromIntegral .
			(read :: String -> Int)) "port number")
		"set port number",
	Option "k" ["key-file"] (ReqArg OptKeyFile "key file") "set key file",
	Option "c" ["cert-file"] (ReqArg OptCertFile "cert file") "set cert file",
	Option "d" ["disable-client-cert"]
		(NoArg OptDisableClientCert) "disable client certification",
	Option "l" ["level"]
		(ReqArg (OptLevel . readCipherSuiteLevel) "cipher suite level")
		"set cipher suite level",
	Option "t" ["test-directory"]
		(ReqArg OptTestDirectory "test directory") "set test directory" ]

readCipherSuiteLevel :: String -> CipherSuiteLevel
readCipherSuiteLevel "ecdsa256" = ToEcdsa256
readCipherSuiteLevel "ecdsa" = ToEcdsa
readCipherSuiteLevel "ecdhe256" = ToEcdhe256
readCipherSuiteLevel "ecdhe" = ToEcdhe
readCipherSuiteLevel "dhe256" = ToDhe256
readCipherSuiteLevel "dhe" = ToDhe
readCipherSuiteLevel "rsa256" = ToRsa256
readCipherSuiteLevel "rsa" = ToRsa
readCipherSuiteLevel _ = NoLevel

optsToPort :: [Option] -> PortID
optsToPort opts = case find isPort opts of
	Just (OptPort p) -> p
	_ -> PortNumber 443
	where
	isPort (OptPort _) = True
	isPort _ = False

optsToKeyFile :: [Option] -> FilePath
optsToKeyFile opts = case find isKeyFile opts of
	Just (OptKeyFile fp) -> fp
	_ -> "localhost.key"
	where
	isKeyFile (OptKeyFile _) = True
	isKeyFile _ = False

optsToCertFile :: [Option] -> FilePath
optsToCertFile opts = case find isCertFile opts of
	Just (OptCertFile fp) -> fp
	_ -> "localhost.crt"
	where
	isCertFile (OptCertFile _) = True
	isCertFile _ = False

optsToCipherSuites :: [Option] -> [CipherSuite]
optsToCipherSuites opts = case find isLevel opts of
	Just (OptLevel l) -> drop (fromEnum l) cipherSuites
	_ -> cipherSuites
	where
	isLevel (OptLevel _) = True
	isLevel _ = False

cipherSuites :: [CipherSuite]
cipherSuites = [
	CipherSuite ECDHE_ECDSA AES_128_CBC_SHA256,
	CipherSuite ECDHE_ECDSA AES_128_CBC_SHA,
	CipherSuite ECDHE_RSA AES_128_CBC_SHA256,
	CipherSuite ECDHE_RSA AES_128_CBC_SHA,
	CipherSuite DHE_RSA AES_128_CBC_SHA256,
	CipherSuite DHE_RSA AES_128_CBC_SHA,
	CipherSuite RSA AES_128_CBC_SHA256,
	CipherSuite RSA AES_128_CBC_SHA ]

optsToTestDirectory :: [Option] -> FilePath
optsToTestDirectory opts = case find isTestDirectory opts of
	Just (OptTestDirectory fp) -> fp
	_ -> "test"

isTestDirectory :: Option -> Bool
isTestDirectory (OptTestDirectory _) = True
isTestDirectory _ = False
