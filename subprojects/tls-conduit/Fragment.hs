module Fragment (
	Fragment(..), readFragment, fragmentToByteString
) where

import Control.Applicative
import System.IO

import Data.Bits
import Data.ByteString (hGet)
import qualified Data.ByteString as BS

import Parts
import Tools

readFragment :: Handle -> IO Fragment
readFragment h = do
	ctvl <- hGet h 5
	let	[ct, vmjr, vmnr, l1, l2] = BS.unpack ctvl
	fragment (contentType ct) (versionGen vmjr vmnr) <$>
		hGet h (fromIntegral l1 `shift` 8 .|. fromIntegral l2)

data Fragment
	= Fragment ContentType Version BS.ByteString
	deriving Show

fragment :: ContentType -> Version -> BS.ByteString -> Fragment
fragment ct v body = Fragment ct v body

fragmentToByteString :: Fragment -> BS.ByteString
fragmentToByteString (Fragment ct v cnt) = contentTypeToByteString ct
	`BS.append` versionToByteString v
	`BS.append` fromLen 2 (BS.length cnt)
	`BS.append` cnt
