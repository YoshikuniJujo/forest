{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module CommandLine (readCommandLine) where

import Control.Applicative ((<$>), (<*>))
import Control.Arrow (first)
import Control.Monad (unless)
import Data.List (find)
import System.Console.GetOpt (getOpt, ArgOrder(..), OptDescr(..), ArgDescr(..))
import System.Exit (exitFailure)
import Network (PortID(..), PortNumber)
import ReadFile (
	readRsaKey, readEcdsaKey, readCertificateChain, readCertificateStore)
import CipherSuite (CipherSuite(..), CipherSuiteKeyEx(..), CipherSuiteMsgEnc(..))

import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA

readCommandLine :: [String] -> IO (
	PortID,
	[CipherSuite],
	FilePath,
	(RSA.PrivateKey, X509.CertificateChain),
	(ECDSA.PrivateKey, X509.CertificateChain),
	Maybe X509.CertificateStore )
readCommandLine args = do
	let	(opts, _, errs) = getOpt Permute options args
	unless (null errs) $ mapM_ putStr errs >> exitFailure
	maybe (return ()) (\msg -> putStr msg >> exitFailure) $ checkOpts opts
	let	port = optsToPort opts
		css = optsToCipherSuites opts
		td = optsToTestDirectory opts
		kfp = optsToKeyFile opts
		cfp = optsToCertFile opts
		ekfp = optsToEcKeyFile opts
		ecfp = optsToEcCertFile opts
	rsa <- (,) <$> readRsaKey kfp <*> readCertificateChain cfp
	ec <- (,) <$> readEcdsaKey ekfp <*> readCertificateChain ecfp
	mcs <- if OptDisableClientCert `elem` opts
		then return Nothing
		else Just <$> readCertificateStore ["cacert.pem"]
	return (port, css, td, rsa, ec, mcs)

data Option
	= OptPort PortID
	| OptDisableClientCert
	| OptLevel CipherSuiteLevel
	| OptTestDirectory FilePath
	| OptKeyFile FilePath
	| OptCertFile FilePath
	| OptEcKeyFile FilePath
	| OptEcCertFile FilePath
	deriving (Show, Eq)

data CipherSuiteLevel
	= ToEcdsa256 | ToEcdsa | ToEcdhe256 | ToEcdhe
	| ToDhe256   | ToDhe   | ToRsa256   | ToRsa
	| NoLevel String
	deriving (Show, Eq)

instance Enum CipherSuiteLevel where
	toEnum 0 = ToEcdsa256
	toEnum 1 = ToEcdsa
	toEnum 2 = ToEcdhe256
	toEnum 3 = ToEcdhe
	toEnum 4 = ToDhe256
	toEnum 5 = ToDhe
	toEnum 6 = ToRsa256
	toEnum 7 = ToRsa
	toEnum _ = NoLevel ""
	fromEnum ToEcdsa256 = 0
	fromEnum ToEcdsa = 1
	fromEnum ToEcdhe256 = 2
	fromEnum ToEcdhe = 3
	fromEnum ToDhe256 = 4
	fromEnum ToDhe = 5
	fromEnum ToRsa256 = 6
	fromEnum ToRsa = 7
	fromEnum (NoLevel _) = 8

options :: [OptDescr Option]
options = [
	Option "p" ["port"]
		(ReqArg (OptPort . PortNumber . read) "port number")
		"set port number",
	Option "k" ["key-file"]
		(ReqArg OptKeyFile "key file") "set key file",
	Option "c" ["cert-file"]
		(ReqArg OptCertFile "cert file") "set cert file",
	Option "K" ["ec-key-file"]
		(ReqArg OptEcKeyFile "EC key file") "set EC key file",
	Option "C" ["ec-cert-file"]
		(ReqArg OptEcCertFile "EC cert file") "set EC cert file",
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
readCipherSuiteLevel l = NoLevel l

checkOpts :: [Option] -> Maybe String
checkOpts opts = case find isNoLevel opts of
	Just (OptLevel (NoLevel l)) -> Just $ "no such level: " ++ l ++ "\n"
	_ -> Nothing
	where
	isNoLevel (OptLevel (NoLevel _)) = True
	isNoLevel _ = False

optsToPort :: [Option] -> PortID
optsToPort opts = case find isPort opts of
	Just (OptPort p) -> p
	_ -> PortNumber 443
	where
	isPort (OptPort _) = True
	isPort _ = False

optsToKeyFile, optsToCertFile :: [Option] -> FilePath
optsToKeyFile opts = case find isKeyFile opts of
	Just (OptKeyFile fp) -> fp
	_ -> "localhost.key"
	where
	isKeyFile (OptKeyFile _) = True
	isKeyFile _ = False

optsToCertFile opts = case find isCertFile opts of
	Just (OptCertFile fp) -> fp
	_ -> "localhost.crt"
	where
	isCertFile (OptCertFile _) = True
	isCertFile _ = False

optsToEcKeyFile, optsToEcCertFile :: [Option] -> FilePath
optsToEcKeyFile opts = case find isEcKeyFile opts of
	Just (OptEcKeyFile fp) -> fp
	_ -> "localhost_ecdsa.key"
	where
	isEcKeyFile (OptEcKeyFile _) = True
	isEcKeyFile _ = False

optsToEcCertFile opts = case find isEcCertFile opts of
	Just (OptEcCertFile fp) -> fp
	_ -> "localhost_ecdsa.cert"
	where
	isEcCertFile (OptEcCertFile _) = True
	isEcCertFile _ = False

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

instance Read PortNumber where
	readsPrec n = map (first (fromIntegral :: Int -> PortNumber)) . readsPrec n
