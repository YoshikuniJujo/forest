{-# LANGUAGE OverloadedStrings, PackageImports, ScopedTypeVariables #-}

module Main (main) where

import Control.Applicative ((<$>), (<*>))
import Control.Monad (unless, forever, void)
import "monads-tf" Control.Monad.State (StateT(..), runStateT, liftIO)
import Control.Concurrent (forkIO)
import Data.List (find)
import System.Environment (getArgs)
import System.Console.GetOpt (getOpt, ArgOrder(..), OptDescr(..), ArgDescr(..))
import System.Exit (exitFailure)
import Network (PortID(..), listenOn, accept)
import "crypto-random" Crypto.Random (SystemRNG, CPRG(..), createEntropyPool)
import MyServer (
	server,
	CipherSuite(..), CipherSuiteKeyEx(..), CipherSuiteMsgEnc(..),
	readRsaKey, readEcPrivKey, readCertificateChain, readCertificateStore)

import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA

main :: IO ()
main = do
	(port, css, rsa, ec, mcs) <- readCommandLine =<< getArgs
	soc <- listenOn port
	g0 :: SystemRNG <- cprgCreate <$> createEntropyPool
	void . (`runStateT` g0) . forever $ do
		(h, _, _) <- liftIO $ accept soc
		g <- StateT $ return . cprgFork
		liftIO . forkIO $ server h g css rsa ec mcs

ecdsaKeyFile, ecdsaCertFile :: String
ecdsaKeyFile = "localhost_ecdsa.key"
ecdsaCertFile = "localhost_ecdsa.cert"

readCommandLine :: [String] -> IO (
	PortID,
	[CipherSuite],
	(RSA.PrivateKey, X509.CertificateChain),
	(ECDSA.PrivateKey, X509.CertificateChain),
	Maybe X509.CertificateStore )
readCommandLine args = do
	let	(opts, pn : kfp : cfp : _, errs) = getOpt Permute options args
		css = optsToCipherSuites opts
	unless (null errs) $ mapM_ putStr errs >> exitFailure
	port <- (PortNumber . fromIntegral <$>) (readIO pn :: IO Int)
	rsa <- (,) <$> readRsaKey kfp <*> readCertificateChain cfp
	ec <- (,) <$> readEcPrivKey ecdsaKeyFile
		<*> readCertificateChain ecdsaCertFile
	mcs <- if OptDisableClientCert `elem` opts
		then return Nothing
		else Just <$> readCertificateStore ["cacert.pem"]
	return (port, css, rsa, ec, mcs)

data Option
	= OptDisableClientCert
	| OptLevel CipherSuiteLevel
	deriving (Show, Eq)

isLevel :: Option -> Bool
isLevel (OptLevel _) = True
isLevel _ = False

data CipherSuiteLevel
	= ToEcdsa256 | ToEcdsa | ToEcdhe256 | ToEcdhe
	| ToDhe256   | ToDhe   | ToRsa256   | ToRsa
	| NoLevel
	deriving (Show, Eq, Enum)

optsToCipherSuites :: [Option] -> [CipherSuite]
optsToCipherSuites opts = case find isLevel opts of
	Just (OptLevel l) -> leveledCipherSuites l
	_ -> cipherSuites

leveledCipherSuites :: CipherSuiteLevel -> [CipherSuite]
leveledCipherSuites l = drop (fromEnum l) cipherSuites

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

options :: [OptDescr Option]
options = [
	Option "d" ["disable-client-cert"]
		(NoArg OptDisableClientCert)
		"disable client certification",
	Option "l" ["level"]
		(ReqArg (OptLevel . readCipherSuiteLevel) "cipher suite level")
		"set cipher suite level" ]
