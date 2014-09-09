{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts,
	PackageImports #-}

module HttpPullTlsSv (
	HttpPullTlsSv, One(..), testPusher,
	) where

import Prelude hiding (filter)

import Control.Applicative
import "monads-tf" Control.Monad.Trans
import Control.Monad.Base
import Control.Monad.Trans.Control
import Control.Concurrent hiding (yield)
import Control.Concurrent.STM
import Data.Maybe
import Data.HandleLike
import Data.Pipe
import Data.Pipe.List
import Data.Pipe.TChan
import Text.XML.Pipe
import Network.TigHTTP.Server
import Network.TigHTTP.Types
import Network.PeyoTLS.Server
import Network.PeyoTLS.ReadFile
import "crypto-random" Crypto.Random

import qualified Data.ByteString.Lazy as LBS

import XmlPusher

data HttpPullTlsSv h = HttpPullTlsSv
	(Pipe () XmlNode (HandleMonad h) ())
	(Pipe XmlNode () (HandleMonad h) ())

instance XmlPusher HttpPullTlsSv where
	type NumOfHandle HttpPullTlsSv = One
	type PusherArg HttpPullTlsSv = (XmlNode -> Bool, XmlNode)
	type PushedType HttpPullTlsSv = Bool
	generate = makeHttpPull
	readFrom (HttpPullTlsSv r _) = r
	writeTo (HttpPullTlsSv _ w) = convert fst =$= w

makeHttpPull :: (ValidateHandle h, MonadBaseControl IO (HandleMonad h)) =>
	One h -> (XmlNode -> Bool, XmlNode) -> HandleMonad h (HttpPullTlsSv h)
makeHttpPull (One h) (ip, ep) = do
	k <- liftBase $ readKey "certs/localhost.sample_key"
	c <- liftBase $ readCertificateChain ["certs/localhost.sample_crt"]
	g <- liftBase (cprgCreate <$> createEntropyPool :: IO SystemRNG)
	(inc, otc) <- (`run` g) $ do
		t <- open h ["TLS_RSA_WITH_AES_128_CBC_SHA"] [(k, c)] Nothing
		runXml t ip ep
	return $ HttpPullTlsSv (fromTChan inc) (toTChan otc)

runXml :: (HandleLike h, MonadBaseControl IO (HandleMonad h)) => h ->
	(XmlNode -> Bool) -> XmlNode -> HandleMonad h (TChan XmlNode, TChan XmlNode)
runXml h ip ep = do
	inc <- liftBase $ atomically newTChan
	otc <- liftBase $ atomically newTChan
	_ <- liftBaseDiscard forkIO . runPipe_ $ talk h ip ep inc otc
	return (inc, otc)

talk :: (HandleLike h, MonadBase IO (HandleMonad h)) =>
	h -> (XmlNode -> Bool) -> XmlNode ->
	TChan XmlNode -> TChan XmlNode -> Pipe () () (HandleMonad h) ()
talk h ip ep inc otc = do
	r <- lift $ getRequest h
	lift . liftBase . print $ requestPath r
	rns <- requestBody r
		=$= xmlEvent
		=$= convert fromJust
		=$= xmlNode []
		=$= toList
	if case rns of [n] -> ip n; _ -> False
	then (flushOr otc ep =$=) . (await >>=) . maybe (return ()) $ \n ->
		lift . putResponse h . responseP $ LBS.fromChunks [xmlString [n]]
	else do	mapM_ yield rns =$= toTChan inc
		(fromTChan otc =$=) . (await >>=) . maybe (return ()) $ \n ->
			lift . putResponse h . responseP
				$ LBS.fromChunks [xmlString [n]]
	talk h ip ep inc otc

responseP :: (HandleLike h, MonadBase IO (HandleMonad h)) =>
	LBS.ByteString -> Response Pipe h
responseP = response

flushOr :: MonadBase IO m => TChan XmlNode -> XmlNode -> Pipe () XmlNode m ()
flushOr c ep = do
	e <- lift . liftBase . atomically $ isEmptyTChan c
	lift . liftBase $ print e
	if e
	then yield ep
	else lift (liftBase . atomically $ readTChan c) >>= yield
