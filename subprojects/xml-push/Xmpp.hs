{-# LANGUAGE OverloadedStrings, ScopedTypeVariables,
	TypeFamilies, FlexibleContexts,
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
import Data.UUID
import System.Random
import Text.XML.Pipe
import Network.Sasl
import Network.XMPiPe.Core.C2S.Client
import "crypto-random" Crypto.Random

import qualified Data.ByteString as BS

import XmlPusher

data Xmpp h = Xmpp Jid (TChan (Maybe BS.ByteString))
	(Pipe () Mpi (HandleMonad h) ())
	(Pipe Mpi () (HandleMonad h) ())

instance XmlPusher Xmpp where
	type NumOfHandle Xmpp = One
	type PusherArg Xmpp = (Jid, BS.ByteString, Jid)
	generate = makeXmpp
	readFrom (Xmpp _you nr r _) = r
		=$= pushId nr
		=$= convert fromMessage
		=$= filter isJust
		=$= convert fromJust
	writeTo (Xmpp you nr _ w) = addRandom
		=$= makeResponse you nr
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

makeResponse :: MonadBase IO m => Jid ->
	TChan (Maybe BS.ByteString) -> Pipe (Maybe (XmlNode, Bool), UUID) Mpi m ()
makeResponse you nr = (await >>=) . maybe (return ()) $ \(mn, r) -> do
	e <- lift . liftBase . atomically $ isEmptyTChan nr
	uuid <- lift $ liftBase randomIO
	if e then maybe (return ()) (yield . makeIqMessage you r uuid) mn else do
		i <- lift . liftBase . atomically $ readTChan nr
		maybe (return ()) yield $ toResponse you mn i uuid
	makeResponse you nr

makeIqMessage :: Jid -> UUID -> UUID -> (XmlNode, Bool) -> Mpi
makeIqMessage you r uuid (n, nr) = if nr then toIq you n r else toMessage you n uuid

toResponse ::
	Jid -> Maybe (XmlNode, Bool) -> Maybe BS.ByteString -> UUID -> Maybe Mpi
toResponse you mn (Just i) _ = case mn of
	Just (n, _) ->
		Just $ Iq (tagsType "result") { tagId = Just i, tagTo = Just you } [n]
	_ -> Just $ Iq (tagsType "result") { tagId = Just i, tagTo = Just you } []
toResponse you mn _ uuid = flip (toMessage you) uuid . fst <$> mn

toIq :: Jid -> XmlNode -> UUID -> Mpi
toIq you n r = Iq
	(tagsType "get") { tagId = Just $ toASCIIBytes r, tagTo = Just you } [n]

toMessage :: Jid -> XmlNode -> UUID -> Mpi
toMessage you n r = Message
	(tagsType "chat") { tagId = Just $ toASCIIBytes r, tagTo = Just you } [n]

mechanisms :: [BS.ByteString]
mechanisms = ["SCRAM-SHA-1", "DIGEST-MD5"]

makeXmpp :: (
	HandleLike h, MonadBase IO (HandleMonad h),
	MonadError (HandleMonad h), Error (ErrorType (HandleMonad h))
	) => One h -> (Jid, BS.ByteString, Jid) -> HandleMonad h (Xmpp h)
makeXmpp (One h) (me, ps, you) = do
	nr <- liftBase $ atomically newTChan
	(g :: SystemRNG) <- liftBase $ cprgCreate <$> createEntropyPool
	let	(cn, _g') = cprgGenerate 32 g
		(Jid un d (Just rsc)) = me
		ss = St [
			("username", un), ("authcid", un), ("password", ps),
			("cnonce", cn) ]
	void . (`evalStateT` ss) . runPipe $ fromHandleLike (THandle h)
		=$= sasl d mechanisms
		=$= toHandleLike (THandle h)
	(Just ns, _fts) <- runWriterT . runPipe $ fromHandleLike (THandle h)
		=$= bind d rsc
		=@= toHandleLike (THandle h)
	runPipe_ $ yield (Presence tagsNull []) =$= output =$= toHandleLike h
	let	r = fromHandleLike h =$= input ns
		w = output =$= toHandleLike h
	return $ Xmpp you nr r w

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
