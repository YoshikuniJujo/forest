{-# LANGUAGE OverloadedStrings, PackageImports #-}

import Control.Applicative
import Control.Monad
import "monads-tf" Control.Monad.Trans
import Data.Maybe
import Data.Pipe
import Data.HandleLike
import Text.XML.Pipe
import Network
import Network.PeyoTLS.Client
import Network.PeyoTLS.ReadFile
import "crypto-random" Crypto.Random

import qualified Data.ByteString as BS

main :: IO ()
main = do
	h <- connectTo "localhost" (PortNumber 5222)
	BS.hPut h $ xmlString begin
	BS.hPut h $ xmlString startTls
	void . runPipe $ handleP h
		=$= xmlEvent
		=$= convert fromJust
		=$= (xmlBegin >>= xmlNodeUntil isProceed)
		=$= printP
	ca <- readCertificateStore ["cacert.sample_pem"]
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	(`run` g) $ do
		p <- open' h "localhost" ["TLS_RSA_WITH_AES_128_CBC_SHA"] [] ca
		hlPut p $ xmlString begin
		void . runPipe $ handleP p
			=$= xmlEvent
			=$= convert fromJust
			=$= (xmlBegin >>= xmlNode)
			=$= printP

begin, startTls :: [XmlNode]
begin = [
	XmlDecl (1, 0),
	XmlStart (("stream", Nothing), "stream")
		[	("", "jabber:client"),
			("stream", "http://etherx.jabber.org/streams") ]
		[	((("", Nothing), "to"), "localhost"),
			((("", Nothing), "version"), "1.0"),
			((("xml", Nothing), "lang"), "en") ] ]
startTls = [
	XmlNode (("", Nothing), "starttls")
		[("", "urn:ietf:params:xml:ns:xmpp-tls")] [] [] ]

isProceed :: XmlNode -> Bool
isProceed (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-tls"), "proceed") _ [] [])
	= True
isProceed _ = False

handleP :: HandleLike h => h -> Pipe () BS.ByteString (HandleMonad h) ()
handleP h = do
	c <- lift $ hlGetContent h
	yield c
	handleP h

printP :: (Show a, Monad m, MonadIO m) => Pipe a () m ()
printP = await >>= maybe (return ()) (\x -> liftIO (print x) >> printP)

convert :: Monad m => (a -> b) -> Pipe a b m ()
convert f = await >>= maybe (return ()) (\x -> yield (f x) >> convert f)
