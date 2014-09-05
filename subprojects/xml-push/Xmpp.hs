{-# LANGUAGE OverloadedStrings, ScopedTypeVariables,
	TypeFamilies, FlexibleContexts,
	UndecidableInstances, PackageImports #-}

module Xmpp (Xmpp, One(..), XmppArgs(..), testPusher) where

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

data Xmpp h = Xmpp
	(XmlNode -> Bool)
	Jid (TChan (Maybe BS.ByteString))
	(Pipe () Mpi (HandleMonad h) ())
	(TChan (Either BS.ByteString (XmlNode, ())))

data XmppArgs = XmppArgs {
	mechanisms :: [BS.ByteString],
	wantResponse :: XmlNode -> Bool,
	iNeedResponse :: XmlNode -> Bool,
	myJid :: Jid,
	passowrd :: BS.ByteString,
	yourJid :: Jid }

instance XmlPusher Xmpp where
	type NumOfHandle Xmpp = One
	type PusherArg Xmpp = XmppArgs
	type PushedType Xmpp = ()
	generate = makeXmpp
	readFrom (Xmpp wr _you nr r wc) = r
		=$= pushId wr nr wc
		=$= convert fromMessage
		=$= filter isJust
		=$= convert fromJust
	writeTo (Xmpp _ you _ _ w) = convert maybeToEither
		=$= toTChan w

maybeToEither :: Maybe a -> Either BS.ByteString a
maybeToEither (Just x) = Right x
maybeToEither _ = Left ""

pushId :: MonadBase IO m => (XmlNode -> Bool) -> TChan (Maybe BS.ByteString) ->
	TChan (Either BS.ByteString (XmlNode, pt)) -> Pipe Mpi Mpi m ()
pushId wr nr wc = (await >>=) . maybe (return ()) $ \mpi -> case mpi of
	Iq Tags { tagType = Just "get", tagId = Just i } [n]
		| wr n -> do
			lift . liftBase . atomically . writeTChan nr $ Just i
			yield mpi >> pushId wr nr wc
		| otherwise -> do
			lift . liftBase . putStrLn $ "MONOLOGUE: " ++ show n
			lift . liftBase . atomically . writeTChan wc $ Left i
			yield mpi >> pushId wr nr wc
	Iq Tags { tagType = Just "set", tagId = Just i } [n]
		| wr n -> do
			lift . liftBase . atomically . writeTChan nr $ Just i
			yield mpi >> pushId wr nr wc
		| otherwise -> do
			lift . liftBase . atomically . writeTChan wc $ Left i
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

makeResponse :: MonadBase IO m =>
	(XmlNode -> Bool) -> Jid ->
	TChan (Maybe BS.ByteString) ->
	Pipe (Either BS.ByteString (XmlNode, pt), UUID) Mpi m ()
makeResponse inr you nr = (await >>=) . maybe (return ()) $ \(mn, r) -> do
	case mn of
		Left i | not $ BS.null i -> do
			either (const $ return ()) yield $
				toResponse you mn (Just i) undefined
		_ -> do	e <- lift . liftBase . atomically $ isEmptyTChan nr
			uuid <- lift $ liftBase randomIO
			if e
			then either (const $ return ())
				(yield . makeIqMessage inr you r uuid) mn
			else do	i <- lift . liftBase . atomically $ readTChan nr
				either (const $ return ()) yield $
					toResponse you mn i uuid
				lift . liftBase . putStrLn $ "HERE: " ++ show i
	makeResponse inr you nr

makeIqMessage :: (XmlNode -> Bool) -> Jid -> UUID -> UUID -> (XmlNode, pt) -> Mpi
makeIqMessage inr you r uuid (n, nr) =
	if inr n then toIq you n r else toMessage you n uuid

toResponse ::
	Jid -> Either BS.ByteString (XmlNode, pt) -> Maybe BS.ByteString -> UUID -> Either BS.ByteString Mpi
toResponse you mn (Just i) _ = case mn of
	Right (n, _) ->
		Right $ Iq (tagsType "result") { tagId = Just i, tagTo = Just you } [n]
	_ -> Right $ Iq (tagsType "result") { tagId = Just i, tagTo = Just you } []
toResponse you mn _ uuid = flip (toMessage you) uuid . fst <$> mn

toIq :: Jid -> XmlNode -> UUID -> Mpi
toIq you n r = Iq
	(tagsType "get") { tagId = Just $ toASCIIBytes r, tagTo = Just you } [n]

toMessage :: Jid -> XmlNode -> UUID -> Mpi
toMessage you n r = Message
	(tagsType "chat") { tagId = Just $ toASCIIBytes r, tagTo = Just you } [n]

makeXmpp :: (
	HandleLike h, MonadBaseControl IO (HandleMonad h),
	MonadError (HandleMonad h), Error (ErrorType (HandleMonad h))
	) => One h -> XmppArgs -> HandleMonad h (Xmpp h)
makeXmpp (One h) (XmppArgs ms wr inr me ps you) = do
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
		=$= addRandom =$= makeResponse inr you nr =$= output =$= toHandleLike h
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
