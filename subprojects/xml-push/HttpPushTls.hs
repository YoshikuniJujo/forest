{-# LANGUAGE OverloadedStrings, TupleSections, ScopedTypeVariables,
	TypeFamilies, FlexibleContexts,
	PackageImports #-}

module HttpPushTls (
	HttpPushTls, HttpPushTlsArgs(..), Two(..), testPusher,
	) where

import Prelude hiding (filter)

import Control.Applicative
import Control.Monad
import "monads-tf" Control.Monad.Trans
import Control.Monad.Base
import Control.Monad.Trans.Control
import Control.Concurrent hiding (yield)
import Control.Concurrent.STM
import Data.Maybe
import Data.HandleLike
import Data.Pipe
import Data.Pipe.Flow
import Data.Pipe.TChan
import Text.XML.Pipe
import Network.TigHTTP.Client
import Network.TigHTTP.Server
import Network.TigHTTP.Types
import Network.PeyoTLS.ReadFile
import Network.PeyoTLS.Client (ValidateHandle)
import "crypto-random" Crypto.Random

import qualified Data.ByteString.Lazy as LBS
import qualified Network.PeyoTLS.Client as Cl
import qualified Network.PeyoTLS.Server as Sv

import XmlPusher

data HttpPushTls h = HttpPushTls {
	needReply :: TVar Bool,
	clientReadChan :: TChan (XmlNode, Bool),
	clientWriteChan :: TChan (Maybe XmlNode),
	serverReadChan :: TChan (XmlNode, Bool),
	serverWriteChan :: TChan (Maybe XmlNode) }

data HttpPushTlsArgs = HttpPushTlsArgs {
	}

instance XmlPusher HttpPushTls where
	type NumOfHandle HttpPushTls = Two
	type PusherArg HttpPushTls = HttpPushTlsArgs
	type PushedType HttpPushTls = Bool
	generate (Two ch sh) = makeHttpPushTls ch sh
	readFrom hp = fromTChans [clientReadChan hp, serverReadChan hp] =$=
		setNeedReply (needReply hp)
	writeTo hp = (convert (((), ) . Just . fst) =$=) . toTChansM $ do
		nr <- liftBase . atomically . readTVar $ needReply hp
		liftBase . atomically $ writeTVar (needReply hp) False
		return [
			(const nr, serverWriteChan hp),
			(const True, clientWriteChan hp) ]

setNeedReply :: MonadBase IO m => TVar Bool -> Pipe (a, Bool) a m ()
setNeedReply nr = await >>= maybe (return ()) (\(x, b) ->
	lift (liftBase . atomically $ writeTVar nr b) >> yield x >> setNeedReply nr)

makeHttpPushTls :: (ValidateHandle h, MonadBaseControl IO (HandleMonad h)) =>
	h -> h -> HttpPushTlsArgs -> HandleMonad h (HttpPushTls h)
makeHttpPushTls ch sh (HttpPushTlsArgs) = do
	v <- liftBase . atomically $ newTVar False
	(ci, co) <- clientC ch
	(si, so) <- talk sh
	return $ HttpPushTls v ci co si so

clientC :: (ValidateHandle h, MonadBaseControl IO (HandleMonad h)) =>
	h -> HandleMonad h (TChan (XmlNode, Bool), TChan (Maybe XmlNode))
clientC h = do
	inc <- liftBase $ atomically newTChan
	otc <- liftBase $ atomically newTChan
	ca <- liftBase $ readCertificateStore ["certs/cacert.sample_pem"]
	(g :: SystemRNG) <- liftBase $ cprgCreate <$> createEntropyPool
	void . liftBaseDiscard forkIO . (`Cl.run` g) $ do
		t <- Cl.open' h "localhost" ["TLS_RSA_WITH_AES_128_CBC_SHA"] [] ca
		runPipe_ $ fromTChan otc
			=$= filter isJust
			=$= convert fromJust
			=$= clientLoop t
			=$= convert (, False)
			=$= toTChan inc
	return (inc, otc)

clientLoop :: (HandleLike h, MonadBaseControl IO (HandleMonad h)) =>
	h -> Pipe XmlNode XmlNode (HandleMonad h) ()
clientLoop h = (await >>=) . maybe (return ()) $ \n -> do
	r <- lift . request h $ post "localhost" 80 "/"
		(Nothing, LBS.fromChunks [xmlString [n]])
	return ()
		=$= responseBody r
		=$= xmlEvent
		=$= convert fromJust
		=$= (xmlNode [] >> return ())
	clientLoop h

talk :: (ValidateHandle h, MonadBaseControl IO (HandleMonad h)) =>
	h -> HandleMonad h (TChan (XmlNode, Bool), TChan (Maybe XmlNode))
talk h = do
	inc <- liftBase $ atomically newTChan
	otc <- liftBase $ atomically newTChan
	k <- liftBase $ readKey "certs/localhost.sample_key"
	c <- liftBase $ readCertificateChain ["certs/localhost.sample_crt"]
	g <- liftBase (cprgCreate <$> createEntropyPool :: IO SystemRNG)
	void . liftBaseDiscard forkIO . (`Sv.run` g) $ do
		t <- Sv.open h ["TLS_RSA_WITH_AES_128_CBC_SHA"] [(k, c)] Nothing
		runPipe_ . forever $ do
			req <- lift $ getRequest t
			requestBody req
				=$= xmlEvent
				=$= convert fromJust
				=$= xmlNode []
				=$= convert (, True)
				=$= toTChan inc
			fromTChan otc =$= await >>= maybe (return ()) (\mn ->
				lift . putResponse t . responseP $ case mn of
					Just n -> LBS.fromChunks [xmlString [n]]
					_ -> "")
	return (inc, otc)

responseP :: HandleLike h => LBS.ByteString -> Response Pipe h
responseP = response
