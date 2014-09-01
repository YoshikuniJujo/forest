{-# LANGUAGE OverloadedStrings, FlexibleContexts, ScopedTypeVariables,
 	PackageImports #-}

import Prelude hiding (filter)

import Control.Applicative
import Control.Monad.Base
import Control.Monad.Trans.Control
import "monads-tf" Control.Monad.State
import "monads-tf" Control.Monad.Writer
import "monads-tf" Control.Monad.Error
import Control.Concurrent hiding (yield)
import Data.Maybe
import Data.HandleLike
import Data.Pipe
import Data.Pipe.Flow
import Data.Pipe.TChan
import Data.Pipe.ByteString
import System.IO
import Text.XML.Pipe
import Network
import Network.PeyoTLS.TChan.Client
import Network.PeyoTLS.ReadFile
import Network.Sasl
import Network.XMPiPe.Core.C2S.Client
import "crypto-random" Crypto.Random

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

class XmlPusher xp where
	generate :: (HandleLike h, ValidateHandle h,
		MonadBaseControl IO (HandleMonad h),
		MonadError (HandleMonad h), Error (ErrorType (HandleMonad h))
		) => h -> HandleMonad h (xp h)
	readFrom :: HandleLike h => xp h -> Pipe () XmlNode (HandleMonad h) ()
	writeTo :: HandleLike h => xp h -> Pipe XmlNode () (HandleMonad h) ()

data Xmpp h = Xmpp
	(Pipe () Mpi (HandleMonad h) ())
	(Pipe Mpi () (HandleMonad h) ())

instance XmlPusher Xmpp where
	generate = makeXmpp
	readFrom (Xmpp r _) = r
		=$= convert fromMessage
		=$= filter isJust
		=$= convert fromJust
	writeTo (Xmpp _ w) = convert toMessage =$= w

makeXmpp :: (HandleLike h, ValidateHandle h,
	MonadBaseControl IO (HandleMonad h),
	MonadError (HandleMonad h), Error (ErrorType (HandleMonad h))
	) => h -> HandleMonad h (Xmpp h)
makeXmpp h = do
	runPipe_ $ fromHandleLike h =$= starttls "localhost" =$= toHandleLike h
	ca <- liftBase $ readCertificateStore ["cacert.sample_pem"]
	(g :: SystemRNG) <- cprgCreate <$> liftBase createEntropyPool
	(inc, otc) <- open' h "localhost" ["TLS_RSA_WITH_AES_128_CBC_SHA"] [] ca g
	(`runStateT` saslState) $ runPipe_ $
		fromTChan inc =$= sasl "localhost" mechanisms =$= toTChan otc
	(Just ns, _fts) <- runWriterT . runPipe $
		fromTChan inc =$= bind "localhost" "profanity" =@= toTChan otc
	runPipe_ $ yield (Presence tagsNull []) =$= output =$= toTChan otc
	let	r = fromTChan inc =$= input ns
		w = output =$= toTChan otc
	return $ Xmpp r w

saslState :: St
saslState = St [
	("username", "yoshikuni"),
	("authcid", "yoshikuni"),
	("password", "password"),
	("cnonce", "00DEADBEEF00") ]

data St = St [(BS.ByteString, BS.ByteString)] deriving Show

instance SaslState St where
	getSaslState (St ss) = ss
	putSaslState ss _ = St ss

mechanisms :: [BS.ByteString]
mechanisms = ["SCRAM-SHA-1", "DIGEST-MD5", "PLAIN"]

fromHandleLike :: HandleLike h => h -> Pipe () BS.ByteString (HandleMonad h) ()
fromHandleLike h = lift (hlGetContent h) >>= yield >> fromHandleLike h

toHandleLike :: HandleLike h => h -> Pipe BS.ByteString () (HandleMonad h) ()
toHandleLike h = await >>= maybe (return ()) ((>> toHandleLike h) . lift . hlPut h)

main :: IO ()
main = do
	h <- connectTo "localhost" $ PortNumber 5222
	(x :: Xmpp Handle) <- generate h
	void . forkIO . runPipe_ $ readFrom x
		=$= convert (BSC.pack . show)
		=$= toHandleLn stdout
	runPipe_ $ fromHandle stdin
		=$= xmlEvent
		=$= convert fromJust
		=$= xmlNode []
		=$= writeTo x

fromMessage :: Mpi -> Maybe XmlNode
fromMessage (Message ts [n]) = Just n
fromMessage (Iq ts [n]) = Just n
fromMessage _ = Nothing

toMessage :: XmlNode -> Mpi
toMessage n = Message (tagsType "chat") {
	tagId = Just "hoge",
	tagTo = Just $ Jid "yoshio" "localhost" Nothing } [n]
