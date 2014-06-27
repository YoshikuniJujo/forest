{-# LANGUAGE OverloadedStrings, ScopedTypeVariables, PackageImports #-}

module TestServer (server, ValidateHandle(..), CipherSuite(..)) where

import Control.Monad (liftM)
import Data.Maybe (fromMaybe)
import Data.HandleLike (HandleLike(..))
import "crypto-random" Crypto.Random (CPRG)

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509
import qualified Crypto.PubKey.RSA as RSA

import TlsServer (
	run, openClient, clientName,
	ValidateHandle(..), CipherSuite(..), SecretKey )

server :: (ValidateHandle h, CPRG g, SecretKey sk) => g -> h ->
	[CipherSuite] ->
	(RSA.PrivateKey, X509.CertificateChain) ->
	(sk, X509.CertificateChain) ->
	Maybe X509.CertificateStore -> HandleMonad h ()
server g h css rsa ec mcs = (`run` g) $ do
	cl <- openClient h css rsa ec mcs
	const () `liftM` doUntil BS.null (hlGetLine cl)
--	doUntil BS.null (hlGetLine cl) >>= mapM_ (hlDebug cl 0 . (`BS.append` "\n"))
	hlPut cl . answer . fromMaybe "Anonym" $ clientName cl
	hlClose cl

answer :: String -> BS.ByteString
answer name = BS.concat [
	"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n",
	"Date: Wed, 07 May 2014 02:27:34 GMT\r\nServer: Warp/2.1.4\r\n",
	"Content-Type: text/plain\r\n\r\n007\r\nHello, \r\n",
	BSC.pack . show $ length name, "\r\n", BSC.pack name, "\r\n",
	"001\r\n!\r\n0\r\n\r\n" ]

doUntil :: Monad m => (a -> Bool) -> m a -> m [a]
doUntil p rd = rd >>= \x ->
	(if p x then return . (: []) else (`liftM` doUntil p rd) . (:)) x
