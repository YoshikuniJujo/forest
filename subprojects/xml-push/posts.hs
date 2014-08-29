{-# LANGUAGE OverloadedStrings, TypeFamilies, TupleSections, ScopedTypeVariables,
	FlexibleContexts,
	PackageImports #-}

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
import Data.Pipe.TChan
import Data.Pipe.ByteString
import System.IO
import System.Environment
import Text.XML.Pipe
import Network
import Network.PeyoTLS.Client
import Network.PeyoTLS.ReadFile
import Network.TigHTTP.Client
import Network.TigHTTP.Types
import "crypto-random" Crypto.Random

import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as LBS

class XmlPusher xp where
	type PusherArg xp
	generate :: (	HandleLike h, ValidateHandle h,
			MonadBaseControl IO (HandleMonad h)
		) => h -> PusherArg xp -> HandleMonad h (xp h)
	readFrom :: HandleLike h => xp h -> Pipe () XmlNode (HandleMonad h) ()
	writeTo :: HandleLike h => xp h -> Pipe XmlNode () (HandleMonad h) ()

data HttpPull h = HttpPull
	(Pipe () XmlNode (HandleMonad h) ())
	(Pipe XmlNode () (HandleMonad h) ())

instance XmlPusher HttpPull where
	type PusherArg HttpPull = (String, FilePath)
	generate = uncurry . mkHttpPull
	readFrom (HttpPull r _) = r
	writeTo (HttpPull _ w) = w

mkHttpPull :: (HandleLike h, ValidateHandle h,
	MonadBaseControl IO (HandleMonad h)
	) =>
	h -> String -> FilePath -> HandleMonad h (HttpPull h)
mkHttpPull h addr pth = do
	(inc, otc) <- do
		ca <- liftBase $ readCertificateStore ["cacert.sample_pem"]
		(g :: SystemRNG) <- liftBase $ cprgCreate <$> createEntropyPool
		(`run` g) $ do
			t <- open h ["TLS_RSA_WITH_AES_128_CBC_SHA"] [] ca
			talkC t addr pth
	let	r = fromTChan inc
		w = toTChan otc
	return $ HttpPull r w

main :: IO ()
main = do
	addr : pth : _ <- getArgs
	h <- connectTo addr $ PortNumber 443

	(hp :: HttpPull Handle) <- mkHttpPull h addr pth

	void . liftBaseDiscard forkIO . runPipe_ $ readFrom hp =$= printP
	runPipe_ $ fromHandle stdin
		=$= xmlEvent
		=$= convert fromJust
		=$= xmlNode []
		=$= writeTo hp

talk :: HandleLike h =>
	h -> String -> FilePath -> Pipe XmlNode XmlNode (HandleMonad h) ()
talk t addr pth = (await >>=) . (maybe (return ())) $ \n -> do
	r <- lift . request t . post addr 443 pth . (Nothing ,) $
		LBS.fromChunks [xmlString [n]]
	void $ return ()
		=$= responseBody r
		=$= xmlEvent
		=$= convert fromJust
		=$= xmlNode []
	talk t addr pth

talkC :: (HandleLike h, MonadBaseControl IO (HandleMonad h)) =>
	h -> String -> FilePath -> HandleMonad h (TChan XmlNode, TChan XmlNode)
talkC t addr pth = do
	inc <- liftBase $ atomically newTChan
	otc <- liftBase $ atomically newTChan
	void . liftBaseDiscard forkIO . runPipe_ $ fromTChan otc
		=$= talk t addr pth
		=$= toTChan inc
	return (inc, otc)

printP :: (MonadBase IO m, Show a) => Pipe a () m ()
printP = await >>= maybe (return ())
	(\s -> lift (liftBase . BSC.putStr . BSC.pack $ show s) >> printP)
