{-# LANGUAGE OverloadedStrings, PackageImports, ScopedTypeVariables #-}

module MyServer (
	server,
	CipherSuite(..), CipherSuiteKeyEx(..), CipherSuiteMsgEnc(..),
--	readRsaKey, readEcPrivKey, readCertificateChain, readCertificateStore,
) where

import "monads-tf" Control.Monad.State
import Data.Maybe (fromMaybe)
import Data.HandleLike (HandleLike(..))
import Data.X509
import Data.X509.CertificateStore
import "crypto-random" Crypto.Random
import Crypto.PubKey.RSA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

import TlsServer (
	SecretKey, CipherSuite(..), CipherSuiteKeyEx(..), CipherSuiteMsgEnc(..),
	ValidateHandle(..), evalClient, openClient, getName)
--	readRsaKey, readEcPrivKey, readCertificateChain, readCertificateStore)

server :: (ValidateHandle h, CPRG g, SecretKey sk) =>
	h -> g -> [CipherSuite] ->
	(PrivateKey, CertificateChain) -> (sk, CertificateChain) ->
	Maybe CertificateStore -> HandleMonad h ()
server h g css rsa ec mcs = (`evalClient` g) $ do
	cl <- openClient h css rsa ec mcs
	doUntil BS.null (hlGetLine cl) >>=
		lift . mapM_ (hlDebug h . (`BS.append` "\n"))
	hlPut cl . answer . fromMaybe "Anonym" $ getName cl
	hlClose cl

answer :: String -> BS.ByteString
answer name = BS.concat [
	"HTTP/1.1 200 OK\r\n", "Transfer-Encoding: chunked\r\n",
	"Date: Wed, 07 May 2014 02:27:34 GMT\r\n", "Server: Warp/2.1.4\r\n",
	"Content-Type: text/plain\r\n\r\n",
	"007\r\n", "Hello, \r\n",
	BSC.pack . show $ length name, "\r\n", BSC.pack name, "\r\n",
	"001\r\n", "!\r\n",
	"0\r\n\r\n" ]

doUntil :: Monad m => (a -> Bool) -> m a -> m [a]
doUntil p rd =
	(\x -> if p x then return [x] else (x :) `liftM` doUntil p rd) =<< rd
