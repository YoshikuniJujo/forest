{-# LANGUAGE PackageImports #-}

module ClientHello (
	ClientHello,
	readClientHello
) where

import Data.ByteString.Lazy (fromStrict, toStrict)
import qualified Data.ByteString as BS
-- import qualified Data.ByteString.Lazy as LBS

import Data.Conduit
import Data.Conduit.Binary
import "monads-tf" Control.Monad.Identity

import Version
import Random
import SessionId
import CipherSuite

readClientHello :: BS.ByteString -> Maybe ClientHello
readClientHello src = runIdentity $
	sourceLbs (fromStrict src) $$ parseClientHello =$ await

parseClientHello :: Monad m => Conduit BS.ByteString m ClientHello
parseClientHello = do
	v <- version
	r <- random
	msid <- sessionId
	cs <- cipherSuites
	case msid of
		Just sid -> yield $ ClientHello v r sid cs
		_ -> return ()

data ClientHello
	= ClientHello Version Random SessionId CipherSuites
	deriving Show
