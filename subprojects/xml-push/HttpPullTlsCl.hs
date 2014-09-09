{-# LANGUAGE OverloadedStrings, TypeFamilies, ScopedTypeVariables, FlexibleContexts,
	PackageImports #-}

module HttpPullTlsCl (
	HttpPullTlsCl, HttpPullTlsClArgs(..), One(..), testPusher,
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
import Network.TigHTTP.Types
import Network.PeyoTLS.ReadFile
import Network.PeyoTLS.TChan.Client
import "crypto-random" Crypto.Random

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as LBS

import XmlPusher

data HttpPullTlsCl h = HttpPullTlsCl
	(Pipe () XmlNode (HandleMonad h) ())
	(Pipe XmlNode () (HandleMonad h) ())

data HttpPullTlsClArgs = HttpPullTlsClArgs {
	domainName :: String,
	portNumber :: Int,
	path :: FilePath,
	poll :: XmlNode,
	isPending :: XmlNode -> Bool,
	duration :: XmlNode -> Maybe Int,
	getPath :: XmlNode -> FilePath
	}

instance XmlPusher HttpPullTlsCl where
	type NumOfHandle HttpPullTlsCl = One
	type PusherArg HttpPullTlsCl = HttpPullTlsClArgs
	type PushedType HttpPullTlsCl = Bool
	generate = makeHttpPull
	readFrom (HttpPullTlsCl r _) = r
	writeTo (HttpPullTlsCl _ w) = filter isJust
		=$= convert (fst . fromJust)
		=$= w

data TChanHandle = TChanHandle (TChan BS.ByteString) (TChan BS.ByteString)

instance HandleLike TChanHandle where
	type HandleMonad TChanHandle = IO
	hlPut (TChanHandle _ o) = atomically . writeTChan o
	hlGet (TChanHandle i _) = atomically . getBS i
	hlGetLine (TChanHandle i _) = atomically $ bsGetLine i
	hlGetContent (TChanHandle i _) = atomically $ readTChan i
	hlDebug _ "critical" = BSC.putStrLn
	hlDebug _ _ = const $ return ()
	hlClose = const $ return ()

bsGetLine :: TChan BS.ByteString -> STM BS.ByteString
bsGetLine c = do
	bs <- readTChan c
	case BSC.span (/= '\n') bs of
		(_, "") -> (bs `BS.append`) <$> bsGetLine c
		(l, r) -> do
			unGetTChan c $ BS.tail r
			return $ chomp l

chomp :: BS.ByteString -> BS.ByteString
chomp bs = case (BSC.null bs, BSC.init bs, BSC.last bs) of
	(True, _, _) -> bs
	(_, ln, '\r') -> ln
	_ -> bs

getBS :: TChan BS.ByteString -> Int -> STM BS.ByteString
getBS _ 0 = return ""
getBS i n = do
	bs <- readTChan i
	if BS.length bs > n
	then do	let (rtn, rst) = BS.splitAt n bs
		unGetTChan i rst
		return rtn
	else (bs `BS.append`) <$> getBS i (n - BS.length bs)

makeHttpPull :: (ValidateHandle h, MonadBaseControl IO (HandleMonad h)) =>
	One h -> HttpPullTlsClArgs -> HandleMonad h (HttpPullTlsCl h)
makeHttpPull (One h) (HttpPullTlsClArgs hn pn fp pl ip gd gp) = do
	dr <- liftBase . atomically $ newTVar Nothing
	(inc, otc) <- do
		ca <- liftBase $ readCertificateStore ["certs/cacert.sample_pem"]
		(g :: SystemRNG) <- liftBase $ cprgCreate <$> createEntropyPool
		(ic, oc) <- open' h "localhost"
			["TLS_RSA_WITH_AES_128_CBC_SHA"] [] ca g
		liftBase $ talkC (TChanHandle ic oc) hn pn fp gp pl ip dr gd
	return $ HttpPullTlsCl (fromTChan inc) (toTChan otc)

talkC :: (HandleLike h, MonadBaseControl IO (HandleMonad h)) =>
	h -> String -> Int -> FilePath -> (XmlNode -> FilePath) ->
	XmlNode -> (XmlNode -> Bool) ->
	TVar (Maybe Int)  -> (XmlNode -> Maybe Int) ->
	HandleMonad h (TChan XmlNode, TChan XmlNode)
talkC h addr pn pth gp pl ip dr gd = do
	lock <- liftBase . atomically $ do
		l <- newTChan
		writeTChan l ()
		return l
	inc <- liftBase $ atomically newTChan
	otc <- liftBase $ atomically newTChan
	inc' <- liftBase $ atomically newTChan
	otc' <- liftBase $ atomically newTChan
	void . liftBaseDiscard forkIO . runPipe_ $ fromTChan otc
		=$= talk lock h addr pn pth gp
		=$= setDuration dr gd
		=$= toTChan inc
	void . liftBaseDiscard forkIO . runPipe_ $ fromTChan otc'
		=$= talk lock h addr pn pth gp
		=$= setDuration dr gd
		=$= toTChan inc'
	void . liftBaseDiscard forkIO . forever $ do
		d <- liftBase . atomically $ do
			md <- readTVar dr
			case md of
				Just d -> return d
				_ -> retry
		liftBase $ threadDelay d
		liftBase $ polling pl ip inc' inc otc'
	return (inc, otc)

setDuration :: MonadBase IO m => TVar (Maybe a) -> (o -> Maybe a) -> Pipe o o m ()
setDuration dr gd = (await >>=) . maybe (return ()) $ \n -> case gd n of
	Just d -> do
		lift . liftBase . atomically $ writeTVar dr (Just d)
		yield n >> setDuration dr gd
	_ -> yield n >> setDuration dr gd

polling :: XmlNode -> (XmlNode -> Bool) ->
	TChan XmlNode -> TChan XmlNode -> TChan XmlNode -> IO ()
polling pl ip i i' o = do
	atomically $ writeTChan o pl
	r <- atomically $ readTChan i
	if ip r
	then atomically (writeTChan i' r) >> polling pl ip i i' o
	else return ()

talk :: (HandleLike h, MonadBase IO (HandleMonad h)) => TChan () ->
	h -> String -> Int -> FilePath -> (XmlNode -> FilePath) ->
	Pipe XmlNode XmlNode (HandleMonad h) ()
talk lock h addr pn pth gp = (await >>=) . (maybe (return ())) $ \n -> do
	let m = LBS.fromChunks [xmlString [n]]
	lift . liftBase . atomically $ readTChan lock
	r <- lift . request h $ post addr pn (pth ++ "/" ++ gp n) (Nothing, m)
	void $ return ()
		=$= responseBody r
		=$= xmlEvent
		=$= convert fromJust
		=$= xmlNode []
	lift . liftBase . atomically $ writeTChan lock ()
	talk lock h addr pn pth gp
