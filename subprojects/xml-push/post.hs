{-# LANGUAGE TypeFamilies, FlexibleContexts, ScopedTypeVariables,
	PackageImports #-}

import Control.Monad
import Control.Monad.Base
import "monads-tf" Control.Monad.Trans
import Control.Monad.Trans.Control
import Control.Concurrent hiding (yield)
import Control.Concurrent.STM
import Data.Maybe
import Data.HandleLike
import Data.Pipe
import Data.Pipe.TChan
import Data.Pipe.ByteString
import System.Environment
import System.IO
import Text.XML.Pipe
import Network
import Network.TigHTTP.Client
import Network.TigHTTP.Types

import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as LBS

class XmlPusher xp where
	type PusherArg xp
	generate :: (HandleLike h, MonadBaseControl IO (HandleMonad h)
		) => h -> PusherArg xp -> HandleMonad h (xp h)
	readFrom :: HandleLike h => xp h -> Pipe () XmlNode (HandleMonad h) ()
	writeTo :: HandleLike h => xp h -> Pipe XmlNode () (HandleMonad h) ()

data HttpPull h = HttpPull
	(Pipe () XmlNode (HandleMonad h) ())
	(Pipe XmlNode () (HandleMonad h) ())

instance XmlPusher HttpPull where
	type PusherArg HttpPull = (String, FilePath)
	generate = makeHttpPull
	readFrom (HttpPull r _) = r
	writeTo (HttpPull _ w) = w

makeHttpPull :: (HandleLike h, MonadBaseControl IO (HandleMonad h)) =>
	h -> (String, FilePath) -> HandleMonad h (HttpPull h)
makeHttpPull h (hn, fp) = do
	(inc, otc) <- talkC h hn fp
	return $ HttpPull (fromTChan inc) (toTChan otc)

main :: IO ()
main = do
	addr : pth : _ <- getArgs
	h <- connectTo addr $ PortNumber 80
	run' h addr pth

run' :: Handle -> String -> FilePath -> IO ()
run' h addr pth = do
	(hp :: HttpPull Handle) <- generate h (addr, pth)
	void . forkIO . runPipe_ $ readFrom hp
		=$= convert (xmlString . (: []))
		=$= (toHandle stdout :: Pipe BSC.ByteString () IO ())
	runPipe_ $ fromHandle stdin
		=$= xmlEvent
		=$= convert fromJust
		=$= xmlNode []
		=$= writeTo hp

talk :: HandleLike h =>
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

talkC :: (HandleLike h, MonadBaseControl IO (HandleMonad h)) =>
	h -> String -> FilePath -> HandleMonad h (TChan XmlNode, TChan XmlNode)
talkC h addr pth = do
	inc <- liftBase $ atomically newTChan
	otc <- liftBase $ atomically newTChan
	void . liftBaseDiscard forkIO . runPipe_ $ fromTChan otc
		=$= talk h addr pth
		=$= toTChan inc
	return (inc, otc)
