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
	path :: FilePath,
	getPath :: XmlNode -> FilePath,
	wantResponse :: XmlNode -> Bool
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
makeHttpPushTls ch sh (HttpPushTlsArgs pt gp wr) = do
	v <- liftBase . atomically $ newTVar False
	(ci, co) <- clientC ch pt gp
	(si, so) <- talk wr sh
	return $ HttpPushTls v ci co si so

clientC :: (ValidateHandle h, MonadBaseControl IO (HandleMonad h)) =>
	h -> FilePath -> (XmlNode -> FilePath) ->
	HandleMonad h (TChan (XmlNode, Bool), TChan (Maybe XmlNode))
clientC h pt gp = do
	inc <- liftBase $ atomically newTChan
	otc <- liftBase $ atomically newTChan
	ca <- liftBase $ readCertificateStore ["certs/cacert.sample_pem"]
	(g :: SystemRNG) <- liftBase $ cprgCreate <$> createEntropyPool
	void . liftBaseDiscard forkIO . (`Cl.run` g) $ do
		t <- Cl.open' h "localhost" ["TLS_RSA_WITH_AES_128_CBC_SHA"] [] ca
		runPipe_ $ fromTChan otc
			=$= filter isJust
			=$= convert fromJust
			=$= clientLoop t pt gp
			=$= convert (, False)
			=$= toTChan inc
	return (inc, otc)

clientLoop :: (HandleLike h, MonadBaseControl IO (HandleMonad h)) =>
	h -> FilePath -> (XmlNode -> FilePath) ->
	Pipe XmlNode XmlNode (HandleMonad h) ()
clientLoop h pt gp = (await >>=) . maybe (return ()) $ \n -> do
	r <- lift . request h $ post "localhost" 80 (pt ++ "/" ++ gp n)
		(Nothing, LBS.fromChunks [xmlString [n]])
	return ()
		=$= responseBody r
		=$= xmlEvent
		=$= convert fromJust
		=$= (xmlNode [] >> return ())
	clientLoop h pt gp

talk :: (ValidateHandle h, MonadBaseControl IO (HandleMonad h)) =>
	(XmlNode -> Bool) ->
	h -> HandleMonad h (TChan (XmlNode, Bool), TChan (Maybe XmlNode))
talk wr h = do
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
				=$= checkReply wr otc
				=$= toTChan inc
			fromTChan otc =$= await >>= maybe (return ()) (\mn ->
				lift . putResponse t . responseP $ case mn of
					Just n -> LBS.fromChunks [xmlString [n]]
					_ -> "")
	return (inc, otc)

checkReply :: MonadBase IO m => (XmlNode -> Bool) -> TChan (Maybe XmlNode) ->
	Pipe XmlNode (XmlNode, Bool) m ()
checkReply wr o = (await >>=) . maybe (return ()) $ \n ->
	if wr n
	then yield (n, True) >> checkReply wr o
	else do	lift . liftBase . atomically $ writeTChan o Nothing
		yield (n, False)
		checkReply wr o

responseP :: HandleLike h => LBS.ByteString -> Response Pipe h
responseP = response
