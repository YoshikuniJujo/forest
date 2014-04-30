module RenegotiationInfo (RenegotiationInfo, renegotiationInfo, renegotiationInfoToByteString) where

import Prelude hiding (take)

import Data.Conduit
import Data.Conduit.Binary

import Data.ByteString.Lazy (toStrict)
import qualified Data.ByteString as BS

import Tools

renegotiationInfo :: Monad m => Conduit BS.ByteString m RenegotiationInfo
renegotiationInfo = do
	len <- getLen 1
	body <- take len
	yield $ RenegotiationInfo $ toStrict body

data RenegotiationInfo = RenegotiationInfo BS.ByteString
	deriving Show

renegotiationInfoToByteString :: RenegotiationInfo -> BS.ByteString
renegotiationInfoToByteString (RenegotiationInfo bs) =
	lenToBS 1 (BS.length bs) `BS.append` bs
