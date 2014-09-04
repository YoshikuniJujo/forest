{-# LANGUAGE OverloadedStrings, TypeFamilies, ScopedTypeVariables, FlexibleContexts,
	PackageImports #-}

module HttpPullTlsCl (
	HttpPullTlsCl, One(..), testPusher,
	) where

import Prelude hiding (filter)

import Control.Applicative
import Control.Monad
import "monads-tf" Control.Monad.Trans
import Control.Monad.Base
import Control.Monad.Trans.Control
import Control.Concurrent
import Control.Concurrent.STM
import Data.Maybe
import Data.HandleLike
import Data.Pipe
import Data.Pipe.Flow
import Data.Pipe.TChan
import Text.XML.Pipe
import Network.TigHTTP.Client
import Network.TigHTTP.Types
import Network.PeyoTLS.ReadFile
import Network.PeyoTLS.Client
import "crypto-random" Crypto.Random

import qualified Data.ByteString.Lazy as LBS

import XmlPusher

data HttpPullTlsCl h = HttpPullTlsCl
	(Pipe () XmlNode (HandleMonad h) ())
	(Pipe XmlNode () (HandleMonad h) ())

instance XmlPusher HttpPullTlsCl where
	type NumOfHandle HttpPullTlsCl = One
	type PusherArg HttpPullTlsCl = (String, FilePath, XmlNode)
	type PushedType HttpPullTlsCl = Bool
	generate = makeHttpPull
	readFrom (HttpPullTlsCl r _) = r
	writeTo (HttpPullTlsCl _ w) = filter isJust
		=$= convert (fst . fromJust)
		=$= w

makeHttpPull :: (ValidateHandle h, MonadBaseControl IO (HandleMonad h)) =>
	One h -> (String, FilePath, XmlNode) -> HandleMonad h (HttpPullTlsCl h)
makeHttpPull (One h) (hn, fp, pl) = do
	(inc, otc) <- do
		ca <- liftBase $ readCertificateStore ["certs/cacert.sample_pem"]
		(g :: SystemRNG) <- liftBase $ cprgCreate <$> createEntropyPool
		(`run` g) $ do
			t <- open h ["TLS_RSA_WITH_AES_128_CBC_SHA"] [] ca
			talkC t hn fp pl
	return $ HttpPullTlsCl (fromTChan inc) (toTChan otc)

talkC :: (HandleLike h, MonadBaseControl IO (HandleMonad h)) =>
	h -> String ->
	FilePath -> XmlNode -> HandleMonad h (TChan XmlNode, TChan XmlNode)
talkC h addr pth pl = do
	inc <- liftBase $ atomically newTChan
	otc <- liftBase $ atomically newTChan
	void . liftBaseDiscard forkIO . runPipe_ $ fromTChan otc
		=$= talk h addr pth
		=$= toTChan inc
	void . liftBaseDiscard forkIO . forever $ do
		liftBase $ threadDelay 15000000
		liftBase . atomically $ writeTChan otc pl
	return (inc, otc)

talk :: (HandleLike h) =>
	h -> String -> FilePath -> Pipe XmlNode XmlNode (HandleMonad h) ()
talk h addr pth = (await >>=) . (maybe (return ())) $ \n -> do
	let m = LBS.fromChunks [xmlString [n]]
	r <- lift . request h $ post addr 80 pth (Nothing, m)
	void $ return ()
		=$= responseBody r
		=$= xmlEvent
		=$= convert fromJust
		=$= xmlNode []
	talk h addr pth
