module ECPointFormat (ECPointFormatList, ecPointFormatList) where

import Prelude hiding (head, take)

import Data.Conduit
import qualified Data.Conduit.List as List
import Data.Conduit.Binary

import Data.Word
import qualified Data.ByteString as BS

import Tools

ecPointFormatList :: Monad m => Conduit BS.ByteString m ECPointFormatList
ecPointFormatList = do
	len <- getLen 1
	body <- take len
	(sourceLbs body $$ parseECPointFormat =$ List.consume) >>= yield

parseECPointFormat :: Monad m => Conduit BS.ByteString m ECPointFormat
parseECPointFormat = do
	mecpf <- head
	case mecpf of
		Just ecpf -> yield $ ecPointFormat ecpf
		_ -> return ()

type ECPointFormatList = [ECPointFormat]

data ECPointFormat
	= Uncompressed
	| ECPointFormatOthers Word8
	deriving Show

ecPointFormat :: Word8 -> ECPointFormat
ecPointFormat 0 = Uncompressed
ecPointFormat w = ECPointFormatOthers w
