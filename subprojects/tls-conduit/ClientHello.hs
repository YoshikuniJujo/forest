{-# LANGUAGE PackageImports #-}

module ClientHello (ClientHello, clientHello) where

import Data.Conduit
import qualified Data.ByteString as BS

import Version
import Random
import SessionId
import CipherSuite
import CompressionMethod
import Extension

clientHello :: Monad m => Conduit BS.ByteString m ClientHello
clientHello = do
	v <- version
	r <- random
	msid <- sessionId
	cs <- cipherSuites
	cm <- compressionMethods
	me <- extensions
	case msid of
		Just sid -> yield $ ClientHello v r sid cs cm me
		_ -> return ()

data ClientHello = ClientHello
	Version Random SessionId CipherSuites CompressionMethods
	(Maybe Extensions)
	deriving Show
