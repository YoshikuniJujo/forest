{-# LANGUAGE OverloadedStrings, TypeFamilies, ScopedTypeVariables,
	FlexibleContexts,
	PackageImports #-}

import Control.Applicative
import "monads-tf" Control.Monad.State
import Control.Monad.Base
import Control.Monad.Trans.Control
import Control.Concurrent hiding (yield)
import Control.Concurrent.STM
import Data.Maybe
import Data.HandleLike
import Data.Pipe
import Data.Pipe.TChan
import Data.Pipe.ByteString
import Data.X509
import System.IO
import Text.XML.Pipe
import Network
import Network.PeyoTLS.Server
import Network.PeyoTLS.ReadFile
import Network.TigHTTP.Server
import Network.TigHTTP.Types
import "crypto-random" Crypto.Random

import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as LBS

class XmlPusher xp where
	type PusherArg xp
	generate :: (ValidateHandle h, MonadBaseControl IO (HandleMonad h)
		) => h -> PusherArg xp -> HandleMonad h (xp h)
	readFrom :: xp h -> Pipe () XmlNode (HandleMonad h) ()
	writeTo :: xp h -> Pipe XmlNode () (HandleMonad h) ()

data HttpPull g h = HttpPull
	(Pipe () XmlNode (HandleMonad h) ())
	(Pipe XmlNode () (HandleMonad h) ())

instance CPRG g => XmlPusher (HttpPull g) where
	type PusherArg (HttpPull g) = TlsArgs g
	generate = makeHttpPull
	readFrom (HttpPull r _) = r
	writeTo (HttpPull _ w) = w

type TlsArgs g = (g, CertSecretKey, CertificateChain)

makeHttpPull :: (
	ValidateHandle h, CPRG g, MonadBaseControl IO (HandleMonad h)) =>
	h -> TlsArgs g -> HandleMonad h (HttpPull g h)
makeHttpPull h (g, k, c) = do
	(inc, otc) <- begin h g k c
	return $ HttpPull (fromTChan inc) (toTChan otc)

begin :: (ValidateHandle h, CPRG g, MonadBaseControl IO (HandleMonad h)) =>
	h -> g -> CertSecretKey -> CertificateChain ->
	HandleMonad h (TChan XmlNode, TChan XmlNode)
begin h g k c = (`run` g) $ do
	t <- open h ["TLS_RSA_WITH_AES_128_CBC_SHA"] [(k, c)] Nothing
	runXml t

main :: IO ()
main = do
	k <- readKey "certs/localhost.sample_key"
	c <- readCertificateChain ["certs/localhost.sample_crt"]
	g0 <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	soc <- listenOn $ PortNumber 443
	void . (`runStateT` g0) . forever $ do
		(h, _, _) <- liftIO $ accept soc
		g <- StateT $ return . cprgFork
		liftIO . forkIO $ do
			(hp :: HttpPull SystemRNG Handle) <- generate h (g, k, c)
			void . liftBaseDiscard forkIO . runPipe_ $ readFrom hp
				=$= convert (xmlString . (: []))
				=$= (toHandleLn stdout ::
					Pipe BSC.ByteString () IO ())
			runPipe_ $ fromHandle stdin
				=$= xmlEvent
				=$= convert fromJust
				=$= xmlNode []
				=$= writeTo hp

runXml :: (HandleLike h, MonadBaseControl IO (HandleMonad h)) =>
	h -> HandleMonad h (TChan XmlNode, TChan XmlNode)
runXml t = do
	inc <- liftBase $ atomically newTChan
	otc <- liftBase $ atomically newTChan
	void . liftBaseDiscard forkIO $ loop t inc otc
	return (inc, otc)

loop :: (HandleLike h, MonadBaseControl IO (HandleMonad h)) =>
	h -> TChan XmlNode -> TChan XmlNode -> HandleMonad h ()
loop t inc otc =  do
	r <- getRequest t
	liftBase . print $ requestPath r
	runPipe_ $ do
		requestBody r
			=$= xmlEvent
			=$= convert fromJust
			=$= xmlNode []
			=$= toTChan inc
		(fromTChan otc =$=) $ (await >>=) $ maybe (return ()) $ \n ->
			lift . putResponse t
				. responseP $ LBS.fromChunks [xmlString [n]]
	loop t inc otc
	hlClose t

responseP :: HandleLike h => LBS.ByteString -> Response Pipe h
responseP = response

printP :: MonadBase IO m => Pipe BSC.ByteString () m ()
printP = await >>= maybe (return ()) (\s -> lift (liftBase $ BSC.putStr s) >> printP)
