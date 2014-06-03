{-# LANGUAGE OverloadedStrings, PackageImports #-}

module DH (
	dhparams, dhprivate, sendServerKeyExchange,
) where

import Control.Applicative
import Data.Maybe
import qualified Data.ByteString as BS
import Crypto.PubKey.DH
import System.IO.Unsafe
import "crypto-random" Crypto.Random
import qualified Crypto.PubKey.RSA as RSA

import Fragment
import Types
import KeyExchange
import Content

version :: Version
version = Version 3 3

dhparams :: Params
dhprivate :: PrivateNumber
(dhparams, dhprivate) = unsafePerformIO $ do
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	let	(ps, g') = generateParams g 512 2
--	let	(ps, g') = generateParams g 256 2
--	let	(ps, g') = generateParams g 128 2
		(pr, _g'') = generatePrivate g' ps
	return (ps, pr)
	
sendServerKeyExchange :: RSA.PrivateKey -> BS.ByteString -> TlsIo ()
sendServerKeyExchange pk sr = do
	Just cr <- getClientRandom
	let	ske = HandshakeServerKeyExchange . addSign pk cr sr $
			ServerKeyExchange
				dhparams (calculatePublic dhparams dhprivate)
				2 1 "hogeru" ""
	((>>) <$> writeFragment <*> fragmentUpdateHash) . contentListToFragment .
		map (ContentHandshake version) $ catMaybes [
		Just ske
	 ]
