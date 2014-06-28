{-# LANGUAGE OverloadedStrings, TypeFamilies, PackageImports, FlexibleContexts #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module TestClient (
	client, CipherSuite(..), KeyExchange(..), BulkEncryption(..),
	ValidateHandle(..) ) where

import TlsClient
import Control.Monad
import "crypto-random" Crypto.Random
import HandshakeBase
import Data.HandleLike

import qualified Data.ByteString as BS
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509

client :: (ValidateHandle h, CPRG g, ClSecretKey sk) => g -> h ->
	(sk, X509.CertificateChain) ->
	X509.CertificateStore ->
	HandleMonad h ()
client g h crt crtS = (`run` g) $ do
	t <- openServer h crt crtS
	hlPut t request
	const () `liftM` hlGetContent t -- >>= hlDebug t 5

request :: BS.ByteString
request = "GET / HTTP/1.1\r\n\r\n"
