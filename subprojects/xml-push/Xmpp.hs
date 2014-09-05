{-# LANGUAGE OverloadedStrings, ScopedTypeVariables,
	TypeFamilies, FlexibleContexts,
	UndecidableInstances, PackageImports #-}

module Xmpp (Xmpp, XmppPushType(..), One(..), XmppArgs(..), testPusher) where

import Prelude hiding (filter)

import Control.Applicative
import "monads-tf" Control.Monad.State
import "monads-tf" Control.Monad.Writer
import "monads-tf" Control.Monad.Error
import Control.Monad.Base
import Control.Monad.Trans.Control
import Control.Concurrent hiding (yield)
import Control.Concurrent.STM
import Data.Maybe
import Data.HandleLike
import Data.Pipe
import Data.Pipe.Flow
import Data.Pipe.TChan
import Data.UUID
import System.Random
import Text.XML.Pipe
import Network.Sasl
import Network.XMPiPe.Core.C2S.Client
import "crypto-random" Crypto.Random

import qualified Data.ByteString as BS

import XmlPusher

data Xmpp pt h = Xmpp
	(XmlNode -> Bool)
	Jid (TChan (Maybe BS.ByteString))
	(Pipe () Mpi (HandleMonad h) ())
	(TChan (Maybe (XmlNode, pt)))

data XmppArgs = XmppArgs {
	mechanisms :: [BS.ByteString],
	wantResponse :: XmlNode -> Bool,
	myJid :: Jid,
	passowrd :: BS.ByteString,
	yourJid :: Jid }

instance XmppPushType pt => XmlPusher (Xmpp pt) where
	type NumOfHandle (Xmpp pt) = One
	type PusherArg (Xmpp pt) = XmppArgs
	type PushedType (Xmpp pt) = pt
	generate = makeXmpp
	readFrom (Xmpp wr _you nr r wc) = r
		=$= pushId wr nr wc
		=$= convert fromMessage
		=$= filter isJust
		=$= convert fromJust
	writeTo (Xmpp _ you _ _ w) = toTChan w

pushId :: MonadBase IO m => (XmlNode -> Bool) -> TChan (Maybe BS.ByteString) ->
	TChan (Maybe (XmlNode, pt)) -> Pipe Mpi Mpi m ()
pushId wr nr wc = (await >>=) . maybe (return ()) $ \mpi -> case mpi of
	Iq Tags { tagType = Just "get", tagId = Just i } [n]
		| wr n -> do
			lift . liftBase . atomically . writeTChan nr $ Just i
			yield mpi >> pushId wr nr wc
		| otherwise -> do
			lift . liftBase . putStrLn $ "MONOLOGUE: " ++ show n
			lift . liftBase . atomically . writeTChan nr $ Just i
			lift . liftBase . atomically $ writeTChan wc Nothing
			yield mpi >> pushId wr nr wc
	Iq Tags { tagType = Just "set", tagId = Just i } [n]
		| wr n -> do
			lift . liftBase . atomically . writeTChan nr $ Just i
			yield mpi >> pushId wr nr wc
		| otherwise -> do
			lift . liftBase . atomically . writeTChan nr $ Just i
			lift . liftBase . atomically $ writeTChan wc Nothing
			yield mpi >> pushId wr nr wc
	Message _ [n]
		| wr n -> do
			lift . liftBase . putStrLn $ "THERE: " ++ show n
			lift . liftBase . atomically $ writeTChan nr Nothing
			yield mpi >> pushId wr nr wc
		| otherwise -> yield mpi >> pushId wr nr wc
	_ -> yield mpi >> pushId wr nr wc

fromMessage :: Mpi -> Maybe XmlNode
fromMessage (Message _ts [n]) = Just n
fromMessage (Iq _ts [n]) = Just n
fromMessage _ = Nothing

addRandom :: (MonadBase IO m, Random r) => Pipe a (a, r) m ()
addRandom = (await >>=) . maybe (return ()) $ \x -> do
	r <- lift $ liftBase randomIO
	yield (x, r)
	addRandom

class XmppPushType tp where
	needResponse :: tp -> Bool

makeResponse :: (MonadBase IO m, XmppPushType pt) => Jid ->
	TChan (Maybe BS.ByteString) -> Pipe (Maybe (XmlNode, pt), UUID) Mpi m ()
makeResponse you nr = (await >>=) . maybe (return ()) $ \(mn, r) -> do
	e <- lift . liftBase . atomically $ isEmptyTChan nr
	uuid <- lift $ liftBase randomIO
	if e
	then maybe (return ()) (yield . makeIqMessage you r uuid) mn
	else do	i <- lift . liftBase . atomically $ readTChan nr
		maybe (return ()) yield $ toResponse you mn i uuid
		lift . liftBase . putStrLn $ "HERE: " ++ show i
	makeResponse you nr

makeIqMessage :: XmppPushType pt => Jid -> UUID -> UUID -> (XmlNode, pt) -> Mpi
makeIqMessage you r uuid (n, nr) =
	if needResponse nr then toIq you n r else toMessage you n uuid

toResponse ::
	Jid -> Maybe (XmlNode, pt) -> Maybe BS.ByteString -> UUID -> Maybe Mpi
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

makeXmpp :: (
	HandleLike h, MonadBaseControl IO (HandleMonad h), XmppPushType pt,
	MonadError (HandleMonad h), Error (ErrorType (HandleMonad h))
	) => One h -> XmppArgs -> HandleMonad h (Xmpp pt h)
makeXmpp (One h) (XmppArgs ms wr me ps you) = do
	nr <- liftBase $ atomically newTChan
	wc <- liftBase $ atomically newTChan
	(g :: SystemRNG) <- liftBase $ cprgCreate <$> createEntropyPool
	let	(cn, _g') = cprgGenerate 32 g
		(Jid un d (Just rsc)) = me
		ss = St [
			("username", un), ("authcid", un), ("password", ps),
			("cnonce", cn) ]
	void . (`evalStateT` ss) . runPipe $ fromHandleLike (THandle h)
		=$= sasl d ms
		=$= toHandleLike (THandle h)
	(Just ns, _fts) <- runWriterT . runPipe $ fromHandleLike (THandle h)
		=$= bind d rsc
		=@= toHandleLike (THandle h)
	runPipe_ $ yield (Presence tagsNull []) =$= output =$= toHandleLike h
	(>> return ()) . liftBaseDiscard forkIO . runPipe_ $ fromTChan wc
		=$= addRandom =$= makeResponse you nr =$= output =$= toHandleLike h
	let	r = fromHandleLike h =$= input ns
	return $ Xmpp wr you nr r wc

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
