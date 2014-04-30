{-# LANGUAGE PackageImports, OverloadedStrings #-}

module ClientHello (ClientHello, clientHello, clientHelloToByteString) where

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

clientHelloToByteString :: ClientHello -> BS.ByteString
clientHelloToByteString (ClientHello v r sid cs cm mext) =
	versionToByteString v
		`BS.append` randomToByteString r
		`BS.append` sessionIdToByteString sid
		`BS.append` cipherSuitesToByteString cs
		`BS.append` compressionMethodsToByteString cm
		`BS.append` maybe "" extensionsToByteString mext
