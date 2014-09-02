{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts,
	UndecidableInstances, PackageImports #-}

module Xmpp (Xmpp, One(..), testPusher) where

import Prelude hiding (filter)

import Control.Applicative
import "monads-tf" Control.Monad.State
import "monads-tf" Control.Monad.Writer
import "monads-tf" Control.Monad.Error
import Control.Monad.Base
import Control.Concurrent.STM
import Data.Maybe
import Data.HandleLike
import Data.Pipe
import Data.Pipe.Flow
import System.Random
import Text.XML.Pipe
import Network.Sasl
import Network.XMPiPe.Core.C2S.Client

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

import XmlPusher

data Xmpp h = Xmpp (TChan (Maybe BS.ByteString))
	(Pipe () Mpi (HandleMonad h) ())
	(Pipe Mpi () (HandleMonad h) ())

instance XmlPusher Xmpp where
	type PusherArg Xmpp = ()
	type NumOfHandle Xmpp = One
	generate = const . makeXmpp
	readFrom (Xmpp nr r _) = r
		=$= pushId nr
		=$= convert fromMessage
		=$= filter isJust
		=$= convert fromJust
	writeTo (Xmpp nr _ w) = addRandom
		=$= makeResponse nr
		=$= w

pushId :: MonadBase IO m => TChan (Maybe BS.ByteString) -> Pipe Mpi Mpi m ()
pushId nr = (await >>=) . maybe (return ()) $ \mpi -> case mpi of
	Iq Tags { tagId = Just i } _ -> do
		lift . liftBase . atomically . writeTChan nr $ Just i
		yield mpi >> pushId nr
	Message _ _ -> do
		lift . liftBase . atomically $ writeTChan nr Nothing
		yield mpi >> pushId nr
	_ -> yield mpi >> pushId nr

fromMessage :: Mpi -> Maybe XmlNode
fromMessage (Message _ts [n]) = Just n
fromMessage (Iq _ts [n]) = Just n
fromMessage _ = Nothing

addRandom :: (MonadBase IO m, Random r) => Pipe a (a, r) m ()
addRandom = (await >>=) . maybe (return ()) $ \x -> do
	r <- lift $ liftBase randomIO
	yield (x, r)
	addRandom

makeResponse :: MonadBase IO m =>
	TChan (Maybe BS.ByteString) -> Pipe (Maybe (XmlNode, Bool), Int) Mpi m ()
makeResponse nr = (await >>=) . maybe (return ()) $ \(mn, r) -> do
	e <- lift . liftBase . atomically $ isEmptyTChan nr
	if e then maybe (return ()) (yield . makeIqMessage r) mn else do
		i <- lift . liftBase . atomically $ readTChan nr
		maybe (return ()) yield $ toResponse mn i
	makeResponse nr

makeIqMessage :: Int -> (XmlNode, Bool) -> Mpi
makeIqMessage r (n, nr) = if nr then toIq n r else toMessage n

toResponse :: Maybe (XmlNode, Bool) -> Maybe BS.ByteString -> Maybe Mpi
toResponse mn (Just i) = case mn of
	Just (n, _) -> Just $ Iq (tagsType "result") {
		tagId = Just i,
		tagTo = Just $ Jid "yoshio" "localhost" (Just "profanity") } [n]
	_ -> Just $ Iq (tagsType "result") {
		tagId = Just i,
		tagTo = Just $ Jid "yoshio" "localhost" (Just "profanity") } []
toResponse mn _ = toMessage . fst <$> mn

toIq :: XmlNode -> Int -> Mpi
toIq n r = Iq (tagsType "get") {
	tagId = Just . BSC.pack $ show r,
	tagTo = Just $ Jid "yoshio" "localhost" (Just "profanity") } [n]

toMessage :: XmlNode -> Mpi
toMessage n = Message (tagsType "chat") {
	tagId = Just "hoge",
	tagTo = Just $ Jid "yoshio" "localhost" Nothing } [n]

mechanisms :: [BS.ByteString]
mechanisms = ["SCRAM-SHA-1", "DIGEST-MD5", "PLAIN"]

makeXmpp :: (
	HandleLike h, MonadBase IO (HandleMonad h),
	MonadError (HandleMonad h), Error (ErrorType (HandleMonad h))
	) => One h -> HandleMonad h (Xmpp h)
makeXmpp (One h) = do
	nr <- liftBase $ atomically newTChan
	let	(Jid un d (Just rsc)) = toJid "yoshikuni@localhost/profanity"
		ss = St [
			("username", un), ("authcid", un), ("password", "password"),
			("cnonce", "00DEADBEEF00") ]
	void . (`evalStateT` ss) . runPipe $ fromHandleLike (THandle h)
		=$= sasl d mechanisms
		=$= toHandleLike (THandle h)
	(Just ns, _fts) <- runWriterT . runPipe $ fromHandleLike (THandle h)
		=$= bind d rsc
		=@= toHandleLike (THandle h)
	runPipe_ $ yield (Presence tagsNull []) =$= output =$= toHandleLike h
	let	r = fromHandleLike h =$= input ns
		w = output =$= toHandleLike h
	return $ Xmpp nr r w

data St = St [(BS.ByteString, BS.ByteString)]
instance SaslState St where getSaslState (St ss) = ss; putSaslState ss _ = St ss

data SHandle s h = SHandle h deriving Show

instance HandleLike h => HandleLike (SHandle s h) where
	type HandleMonad (SHandle s h) = StateT s (HandleMonad h)
	hlPut (SHandle h) = lift . hlPut h
	hlGet (SHandle h) = lift . hlGet h
	hlClose (SHandle h) = lift $ hlClose h

data THandle (t :: (* -> *) -> * -> *) h = THandle h deriving Show

instance (MonadTrans t, HandleLike h, Monad (t (HandleMonad h))) =>
	HandleLike (THandle t h) where
	type HandleMonad (THandle t h) = t (HandleMonad h)
	hlPut (THandle h) = lift . hlPut h
	hlGet (THandle h) = lift . hlGet h
	hlClose (THandle h) = lift $ hlClose h

fromHandleLike :: HandleLike h => h -> Pipe () BS.ByteString (HandleMonad h) ()
fromHandleLike h = lift (hlGetContent h) >>= yield >> fromHandleLike h

toHandleLike :: HandleLike h => h -> Pipe BS.ByteString () (HandleMonad h) ()
toHandleLike h = await >>= maybe (return ()) ((>> toHandleLike h) . lift . hlPut h)
