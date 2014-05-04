module SessionId (SessionId, sessionId, sessionIdToByteString) where

import Prelude hiding (take, head)

import Data.Conduit
import Data.Conduit.Binary

import Data.ByteString.Lazy (toStrict)
import qualified Data.ByteString as BS

import Tools

data SessionId = SessionId BS.ByteString
	deriving Show

sessionId :: Monad m => Consumer BS.ByteString m (Maybe SessionId)
sessionId = do
	ml <- head
	case ml of
		Just l -> do
			body <- take $ fromIntegral l
			return . Just . SessionId $ toStrict body
		_ -> return Nothing

sessionIdToByteString :: SessionId -> BS.ByteString
sessionIdToByteString (SessionId bs) =
	lenToBS 1 (BS.length bs) `BS.append` bs
