{-# LANGUAGE TypeFamilies, OverloadedStrings, FlexibleContexts #-}

import Control.Monad
import qualified Data.ByteString as BS
import System.IO

class Monad (HandleMonad h) => HandleLike h where
	type HandleMonad h
	hlGet :: h -> Int -> HandleMonad h BS.ByteString
	hlPut :: h -> BS.ByteString -> HandleMonad h ()

instance HandleLike Handle where
	type HandleMonad Handle = IO
	hlGet = BS.hGet
	hlPut = BS.hPut

putHello :: (HandleLike h, HandleMonad h ~ IO) => h -> IO ()
putHello h = hlPut h "Hello\n"

putReverse :: HandleLike h => h -> BS.ByteString -> HandleMonad h ()
putReverse h = hlPut h . BS.reverse

data Tls h = Tls h BS.ByteString BS.ByteString

instance HandleLike h => HandleLike (Tls h) where
	type HandleMonad (Tls h) = HandleMonad h
	hlGet (Tls h hello world) = ((hello `BS.append`) `liftM`) . hlGet h
	hlPut (Tls h hello world) = hlPut h . (world `BS.append`)

openTls :: HandleLike h => h -> BS.ByteString -> BS.ByteString ->
	HandleMonad h (Tls h)
openTls h hello world = do
	hlPut h $ "put " `BS.append` hello `BS.append` " if read"
	hlPut h $ "put " `BS.append` world `BS.append` " if write"
	return $ Tls h hello world
