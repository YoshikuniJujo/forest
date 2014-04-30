module ServerHello (ServerHello, serverHello) where

import Data.Conduit
import Data.Conduit.Binary

import qualified Data.ByteString as BS

import Version
import Random
import SessionId
import CipherSuite
import CompressionMethod
-- import ServerExtension
import Extension

serverHello :: Monad m => Conduit BS.ByteString m ServerHello
serverHello = do
	v <- version
	r <- random
	msid <- sessionId
	cs <- parseCipherSuite
	cm <- parseCompressionMethod
	me <- extensions
	case msid of
		Just sid -> yield $ ServerHello v r sid cs cm me
		_ -> return ()

data ServerHello
	= ServerHello Version Random SessionId CipherSuite CompressionMethod
		(Maybe Extensions)
	deriving Show
