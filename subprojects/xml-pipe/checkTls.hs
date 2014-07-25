{-# LANGUAGE OverloadedStrings, PackageImports #-}

import Control.Applicative
import Control.Monad
import "monads-tf" Control.Monad.Trans
import Data.Pipe
import Data.Pipe.List
import Data.HandleLike
import System.IO
import Network
import Network.PeyoTLS.Client
import Network.PeyoTLS.ReadFile
import "crypto-random" Crypto.Random

import qualified Data.ByteString as BS

import XmlCreate

main :: IO ()
main = do
	h <- connectTo "localhost" (PortNumber 5222)
	BS.hPut h begin
	BS.hPut h startTls
	hFlush h
	mu <- runPipe $ handleP h
		=$= xmlEvent
		=$= filterJust
--		=$= (xmlBegin >>= xmlNode)
		=$= xmlPipe1
		=$= puts
	case mu of
		Just _ -> return ()
		_ -> error "bad in main"
	ca <- readCertificateStore ["cacert.pem"]
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	(`run` g) $ do
		p <- open' h "localhost" ["TLS_RSA_WITH_AES_128_CBC_SHA"] [] ca
		hlPut p begin
		runPipe $ handleP p
			=$= xmlEvent
			=$= filterJust
			=$= xmlPipe
			=$= puts
		return ()

xmlPipe1 :: Monad m => Pipe XmlEvent XmlNode m ()
xmlPipe1 = xmlBegin >>= flip xmlNodeUntil isProceed

xmlPipe :: Monad m => Pipe XmlEvent XmlNode m ()
xmlPipe = do
	c <- xmlBegin >>= xmlNode
	when c $ xmlPipe

isProceed :: XmlNode -> Bool
isProceed (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-tls"), "proceed") _ [] [])
	= True
isProceed _ = False

puts :: Show a => (Monad m, MonadIO m) => Pipe a () m ()
puts = await >>= maybe (return ()) (\bs -> liftIO (print bs) >> puts)

filterJust :: Monad m => Pipe (Maybe a) a m ()
filterJust = do
	mmx <- await
	case mmx of
		Just (Just x) -> yield x >> filterJust
		Just _ -> error "filterJust" -- filterJust
		_ -> return ()

begin, startTls :: BS.ByteString
begin = BS.concat [
	"<?xml version='1.0'?>",
	"<stream:stream to='localhost' xml:lang='en' version='1.0' ",
	"xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>"
	]
startTls = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"

handleP' :: Handle -> Pipe () BS.ByteString IO ()
handleP' h = do
	c <- lift $ BS.hGet h 1
	lift $ print c
	yield c
	handleP' h

handleP :: HandleLike h => h -> Pipe () BS.ByteString (HandleMonad h) ()
handleP h = do
	c <- lift $ hlGetContent h
--	lift $ hlDebug h "critical" c
	yield c
	handleP h
