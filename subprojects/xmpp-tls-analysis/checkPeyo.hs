{-# LANGUAGE OverloadedStrings, PackageImports #-}

import Control.Applicative
import Control.Monad
import "monads-tf" Control.Monad.Trans
import Data.HandleLike
import System.IO
import Network
import Network.PeyoTLS.Client
import Network.PeyoTLS.ReadFile
import "crypto-random" Crypto.Random

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

main :: IO ()
main = do
	h <- connectTo "localhost" (PortNumber 5222)
	BS.hPut h $ begin
	getTag h >>= print
	getTag h >>= print
	getTag h >>= print
	getTag h >>= print
	getTag h >>= print
	getTag h >>= print
	getTag h >>= print
	getTag h >>= print
	getTag h >>= print
	getTag h >>= print
	getTag h >>= print
	BS.hPut h $ startTls
	getTag h >>= print
	ca <- readCertificateStore ["cacert.pem"]
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	(`run` g) $ do
		p <- open' h "localhost" ["TLS_RSA_WITH_AES_128_CBC_SHA"] [] ca
		hlPut p begin
		getTag p >>= liftIO . print
		getTag p >>= liftIO . print
		getTag p >>= liftIO . print
		getTag p >>= liftIO . print
		getTag p >>= liftIO . print
		getTag p >>= liftIO . print
		getTag p >>= liftIO . print
		getTag p >>= liftIO . print
		getTag p >>= liftIO . print
		getTag p >>= liftIO . print
		getTag p >>= liftIO . print
		getTag p >>= liftIO . print
		getTag p >>= liftIO . print

begin :: BS.ByteString
begin = BS.concat [
	"<?xml version='1.0'?>",
	"<stream:stream to='localhost' xml:lang='en' verion='1.0' ",
	"xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>"
	]

startTls :: BS.ByteString
startTls = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"

getTag :: HandleLike h => h -> HandleMonad h BS.ByteString
getTag h = do
	c <- hlGet h 1
	case c of
		">" -> return c
		_ -> BSC.append c `liftM` getTag h
