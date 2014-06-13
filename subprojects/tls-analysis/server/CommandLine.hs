{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module CommandLine (readCommandLine) where

import Control.Applicative ((<$>), (<*>))
import Control.Arrow (first)
import Control.Monad (unless)
import Data.Maybe (fromMaybe)
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
	PortID, [CipherSuite], FilePath,
	(RSA.PrivateKey, X509.CertificateChain),
	(ECDSA.PrivateKey, X509.CertificateChain),
	Maybe X509.CertificateStore )
readCommandLine args = do
	let (os, as, errs) = getOpt Permute options args
	unless (null errs) $ mapM_ putStr errs >> exitFailure
	unless (null as) $ putStrLn ("naked args: " ++ show as) >> exitFailure
	opts <- either (\msg -> putStr msg >> exitFailure) return $ classify os
	let	port = PortNumber 443 `fromMaybe` optPort opts
		css = maybe id (drop . fromEnum) (optLevel opts) cipherSuites
		td = "test" `fromMaybe` optTestDirectory opts
		kfp = "localhost.key" `fromMaybe` optKeyFile opts
		cfp = "localhost.crt" `fromMaybe` optCertFile opts
		ekfp = "localhost_ecdsa.key" `fromMaybe` optEcKeyFile opts
		ecfp = "localhost_ecdsa.cert" `fromMaybe` optEcCertFile opts
	rsa <- (,) <$> readRsaKey kfp <*> readCertificateChain cfp
	ec <- (,) <$> readEcdsaKey ekfp <*> readCertificateChain ecfp
	mcs <- if optDisableClientCert opts then return Nothing else
		Just <$> readCertificateStore ["cacert.pem"]
	return (port, css, td, rsa, ec, mcs)

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

data Options = Options {
	optPort :: Maybe PortID,
	optDisableClientCert :: Bool,
	optLevel :: Maybe CipherSuiteLevel,
	optTestDirectory :: Maybe FilePath,
	optKeyFile :: Maybe FilePath,
	optCertFile :: Maybe FilePath,
	optEcKeyFile :: Maybe FilePath,
	optEcCertFile :: Maybe FilePath }
	deriving Show

initialOptions :: Options
initialOptions = Options {
	optPort = Nothing,
	optDisableClientCert = False,
	optLevel = Nothing,
	optTestDirectory = Nothing,
	optKeyFile = Nothing,
	optCertFile = Nothing,
	optEcKeyFile = Nothing,
	optEcCertFile = Nothing }

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

classify :: [Option] -> Either String Options
classify [] = return initialOptions
classify (o : os) = do
	c <- classify os
	case o of
		OptPort p -> ck (optPort c) >> return c { optPort = Just p }
		OptDisableClientCert -> if optDisableClientCert c
			then Left "duplicated -d options\n"
			else return c { optDisableClientCert = True }
		OptLevel (NoLevel l) -> Left $ "no such level " ++ show l ++ "\n"
		OptLevel csl ->
			ck (optLevel c) >> return c { optLevel = Just csl }
		OptTestDirectory td -> 
			ck (optTestDirectory c) >>
				return c { optTestDirectory = Just td }
		OptKeyFile kf ->
			ck (optKeyFile c) >> return c { optKeyFile = Just kf }
		OptCertFile cf ->
			ck (optCertFile c) >> return c { optCertFile = Just cf }
		OptEcKeyFile ekf ->
			ck (optEcKeyFile c) >> return c { optEcKeyFile = Just ekf }
		OptEcCertFile ecf ->
			ck (optEcCertFile c) >>
				return c { optEcCertFile = Just ecf }
	where
	ck (Just x) = Left $ "Can't set: already " ++ show x ++ "\n"
	ck _ = Right ()

instance Read PortNumber where
	readsPrec n = map (first (fromIntegral :: Int -> PortNumber)) . readsPrec n
