{-# LANGUAGE TupleSections #-}

module Fragment (
	Fragment(..), readFragment, fragmentToByteString
) where

import Prelude hiding (init)

import System.IO

import Data.Bits
import Data.ByteString (hGet)
import qualified Data.ByteString as BS

import Parts
import Tools

import qualified Crypto.Hash.MD5 as MD5
import qualified Crypto.Hash.SHA1 as SHA1

import Data.IORef
import System.IO.Unsafe

md5Ctx :: IORef MD5.Ctx
md5Ctx = unsafePerformIO $ newIORef MD5.init

sha1Ctx :: IORef SHA1.Ctx
sha1Ctx = unsafePerformIO $ newIORef SHA1.init

updateMD5 :: BS.ByteString -> IO ()
updateMD5 bs = modifyIORef md5Ctx (`MD5.update` bs)

updateSHA1 :: BS.ByteString -> IO ()
updateSHA1 bs = modifyIORef sha1Ctx (`SHA1.update` bs)

readFragment :: Handle -> IO (Fragment, (MD5.Ctx, SHA1.Ctx))
readFragment h = do
	ctvl <- hGet h 5
--	updateMD5 ctvl
--	updateSHA1 ctvl
	let	[ct, vmjr, vmnr, l1, l2] = BS.unpack ctvl
	body <- hGet h (fromIntegral l1 `shift` 8 .|. fromIntegral l2)
	updateMD5 body
	updateSHA1 body
	putStrLn $ "Update  : " ++ show body
	readIORef md5Ctx >>= putStrLn . ("MD5 now: " ++) . show . MD5.finalize
	readIORef sha1Ctx >>= putStrLn . ("SHA1 now: " ++) . show . SHA1.finalize
	md5 <- readIORef md5Ctx
	sha1 <- readIORef sha1Ctx
	return (fragment (contentType ct) (versionGen vmjr vmnr) body , (md5, sha1))

data Fragment
	= Fragment ContentType Version BS.ByteString
	deriving Show

fragment :: ContentType -> Version -> BS.ByteString -> Fragment
-- fragment ct v body = Fragment ct v body
fragment = Fragment

fragmentToByteString :: Fragment -> BS.ByteString
fragmentToByteString (Fragment ct v cnt) = contentTypeToByteString ct
	`BS.append` versionToByteString v
	`BS.append` fromLen 2 (BS.length cnt)
	`BS.append` cnt
