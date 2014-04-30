module ServerName (ServerNameList, serverNameList) where

import Prelude hiding (take, head)

import Data.Conduit
import qualified Data.Conduit.List as List
import Data.Conduit.Binary

import Data.Word
import Data.ByteString.Lazy (toStrict)
import qualified Data.ByteString as BS

import Tools

serverNameList :: Monad m => Conduit BS.ByteString m ServerNameList
serverNameList = do
	mlen <- maybeLen 2
	case mlen of
		Just len -> do
			body <- take len
			(sourceLbs body $$ parseServerName =$ List.consume) >>= yield
		_ -> return ()

parseServerName :: Monad m => Conduit BS.ByteString m ServerName
parseServerName = do
	mnt <- head
	case mnt of
		Just nt -> do
			len <- getLen 2
			body <- take len
			yield $ serverName (nameType nt) (toStrict body)
			parseServerName
		_ -> return ()

type ServerNameList = [ServerName]

data ServerName
	= ServerNameHostName BS.ByteString
	| ServerNameOthers NameType BS.ByteString
	deriving Show

serverName :: NameType -> BS.ByteString -> ServerName
serverName NameTypeHostName body = ServerNameHostName body
serverName nt body = ServerNameOthers nt body

data NameType
	= NameTypeHostName
	| NameTypeOthers Word8
	deriving Show

nameType :: Word8 -> NameType
nameType 0 = NameTypeHostName
nameType w = NameTypeOthers w
