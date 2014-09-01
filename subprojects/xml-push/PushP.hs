{-# LANGUAGE OverloadedStrings, TupleSections, ScopedTypeVariables,
	TypeFamilies, FlexibleContexts, PackageImports #-}

module PushP (
	XmlPusher(..), HttpPush, Two(..),
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
import Network.PeyoTLS.ReadFile
import Network.TigHTTP.Client
import Network.TigHTTP.Server
import Network.TigHTTP.Types
import "crypto-random" Crypto.Random

import qualified Data.ByteString.Lazy as LBS
import qualified Network.PeyoTLS.Client as PC
import qualified Network.PeyoTLS.Server as PS

class XmlPusher xp where
	type PusherArg xp
	type NumOfHandle xp :: * -> *
	generate :: (PC.ValidateHandle h, MonadBaseControl IO (HandleMonad h)
		) => NumOfHandle xp h -> PusherArg xp -> HandleMonad h (xp h)
	readFrom :: (HandleLike h, MonadBase IO (HandleMonad h)) =>
		xp h -> Pipe () XmlNode (HandleMonad h) ()
	writeTo :: (HandleLike h, MonadBase IO (HandleMonad h)) =>
		xp h -> Pipe (Maybe XmlNode) () (HandleMonad h) ()

data Two h = Two h h deriving Show

data HttpPush h = HttpPush {
	needReply :: TVar Bool,
	clientReadChan :: TChan (XmlNode, Bool),
	clientWriteChan :: TChan (Maybe XmlNode),
	serverReadChan :: TChan (XmlNode, Bool),
	serverWriteChan :: TChan (Maybe XmlNode) }

instance XmlPusher HttpPush where
	type PusherArg HttpPush = ()
	type NumOfHandle HttpPush = Two
	generate (Two ch sh) () = mkHttpPush ch sh
	readFrom hp = fromTChans [clientReadChan hp, serverReadChan hp] =$=
		setNeedReply (needReply hp)
	writeTo hp = (convert (() ,) =$=) . toTChansM $ do
		nr <- liftBase . atomically . readTVar $ needReply hp
		liftBase . atomically $ writeTVar (needReply hp) False
		liftBase $ print nr
		return [
			(const nr, serverWriteChan hp),
			(const True, clientWriteChan hp) ]

setNeedReply :: MonadBase IO m => TVar Bool -> Pipe (a, Bool) a m ()
setNeedReply nr = await >>= maybe (return ()) (\(x, b) ->
	lift (liftBase . atomically $ writeTVar nr b) >> yield x >> setNeedReply nr)

mkHttpPush :: (
	PC.ValidateHandle h, MonadBaseControl IO (HandleMonad h)
	) => h -> h -> HandleMonad h (HttpPush h)
mkHttpPush ch sh = do
	v <- liftBase . atomically $ newTVar False
	(ci, co) <- clientC ch
	(si, so) <- talk sh
	return $ HttpPush v ci co si so

talk :: (PS.ValidateHandle h, MonadBaseControl IO (HandleMonad h)
	) => h -> HandleMonad h (TChan (XmlNode, Bool), TChan (Maybe XmlNode))
talk h = do
	inc <- liftBase $ atomically newTChan
	otc <- liftBase $ atomically newTChan
	k <- liftBase $ readKey "localhost.sample_key"
	c <- liftBase $ readCertificateChain ["localhost.sample_crt"]
	g0 <- liftBase (cprgCreate <$> createEntropyPool :: IO SystemRNG)
	void . liftBaseDiscard forkIO . (`PS.run` g0) $ do
		t <- PS.open h ["TLS_RSA_WITH_AES_128_CBC_SHA"] [(k, c)] Nothing
		runPipe_ . forever $ do
			req <- lift $ getRequest t
			lift . liftBase . print $ requestPath req
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

clientC :: (PC.ValidateHandle h, MonadBaseControl IO (HandleMonad h)
	) => h -> HandleMonad h (TChan (XmlNode, Bool), TChan (Maybe XmlNode))
clientC h = do
	inc <- liftBase $ atomically newTChan
	otc <- liftBase $ atomically newTChan
	ca <- liftBase $ readCertificateStore ["cacert.sample_pem"]
	(g :: SystemRNG) <- liftBase $ cprgCreate <$> createEntropyPool
	void . liftBaseDiscard forkIO . (`PC.run` g) $ do
		t <- PC.open' h "localhost" ["TLS_RSA_WITH_AES_128_CBC_SHA"] [] ca
		runPipe_ $ fromTChan otc
			=$= filter isJust
			=$= convert fromJust
			=$= clientLoop t
			=$= convert (, False)
			=$= toTChan inc
	return (inc, otc)

clientLoop :: (HandleLike h, MonadBaseControl IO (HandleMonad h)
	) => h -> Pipe XmlNode XmlNode (HandleMonad h) ()
clientLoop h = (await >>=) . maybe (return ()) $ \n -> do
	r <- lift . request h $ post "localhost" 80 "/"
				(Nothing, LBS.fromChunks [xmlString [n]])
	return ()
		=$= responseBody r
		=$= xmlEvent
		=$= convert fromJust
		=$= (xmlNode [] >> return ())
	clientLoop h
