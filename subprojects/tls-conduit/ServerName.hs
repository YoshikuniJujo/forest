module ServerName (ServerName, serverName) where

import Data.Conduit
import Data.Conduit.Binary

import qualified Data.ByteString as BS

serverName :: Monad m => Consumer BS.ByteString m ServerName
serverName = return ServerName

data ServerName
	= ServerName
	deriving Show
