{-# LANGUAGE OverloadedStrings, TypeFamilies, FlexibleContexts,
	ScopedTypeVariables, PackageImports #-}

import Prelude hiding (filter)

import Control.Applicative
import "monads-tf" Control.Monad.State
import "monads-tf" Control.Monad.Writer
import "monads-tf" Control.Monad.Error
import Control.Monad.Base
import Control.Concurrent hiding (yield)
import Control.Concurrent.STM
import Data.Maybe
import Data.Pipe
import Data.Pipe.Flow
import Data.Pipe.IO (debug)
import Data.Pipe.ByteString
import Data.HandleLike
import System.IO
import System.Random
import Text.XML.Pipe
import Network
import Network.Sasl
import Network.XMPiPe.Core.C2S.Client

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

class XmlPusher xp where
	generate :: (HandleLike h,
		MonadError (HandleMonad h), Error (ErrorType (HandleMonad h)),
		MonadBase IO (HandleMonad h)
		) => h -> HandleMonad h (xp h)
	readFrom :: (HandleLike h, MonadBase IO (HandleMonad h)) =>
		xp h -> Pipe () XmlNode (HandleMonad h) ()
	writeTo :: (HandleLike h, MonadBase IO (HandleMonad h)) =>
		xp h -> Pipe (Maybe XmlNode) () (HandleMonad h) ()

{-
data Xml h = Xml
	(Pipe () XmlNode (HandleMonad h) ())
	(Pipe XmlNode () (HandleMonad h) ())

instance XmlPusher Xml where
	generate = makeXml
	readFrom (Xml r _) = r
	writeTo (Xml _ w) = w

makeXml :: HandleLike h => h -> HandleMonad h (Xml h)
makeXml h = return $ Xml r w
	where
	r = fromHandleLike h
		=$= xmlEvent =$= convert fromJust =$= xmlNode [] >> return ()
	w = convert (xmlString . (: [])) =$= toHandleLike h
	-}

data Xmpp h = Xmpp (TChan (Maybe BS.ByteString))
	(Pipe () Mpi (HandleMonad h) ())
	(Pipe Mpi () (HandleMonad h) ())

instance XmlPusher Xmpp where
	generate = makeXmpp
	readFrom (Xmpp nr r _) = r
		=$= debug
		=$= pushId nr
		=$= convert fromMessage
		=$= filter isJust
		=$= convert fromJust
	writeTo (Xmpp nr _ w) = addRandom
		=$= makeResponse nr
--		=$= convert (uncurry toIq)
		=$= w

makeResponse :: MonadBase IO m =>
	TChan (Maybe BS.ByteString) -> Pipe (Maybe XmlNode, Int) Mpi m ()
makeResponse nr = (await >>=) . maybe (return ()) $ \(mn, r) -> do
	e <- lift . liftBase . atomically $ isEmptyTChan nr
	if e then maybe (return ()) (yield . flip toIq r) mn else do
		i <- lift . liftBase . atomically $ readTChan nr
		maybe (return ()) yield $ toResponse mn i
	makeResponse nr

pushId :: MonadBase IO m => TChan (Maybe BS.ByteString) -> Pipe Mpi Mpi m ()
pushId nr = (await >>=) . maybe (return ()) $ \mpi -> case mpi of
	Iq Tags { tagId = Just i } _ -> do
		lift (liftBase . atomically . writeTChan nr $ Just i)
		yield mpi
		pushId nr
	Message _ _ -> do
		lift (liftBase . atomically $ writeTChan nr Nothing)
		yield mpi
		pushId nr
	_ -> yield mpi >> pushId nr

makeXmpp :: (HandleLike h,
	MonadError (HandleMonad h), Error (ErrorType (HandleMonad h)),
	MonadBase IO (HandleMonad h)
	) => h -> HandleMonad h (Xmpp h)
makeXmpp h = do
	nr <- liftBase $ atomically newTChan
	let	me@(Jid un d (Just rsc)) = toJid "yoshikuni@localhost/profanity"
		you = toJid "yoshio@localhost"
		ss = St [
			("username", un), ("authcid", un), ("password", "password"),
			("cnonce", "00DEADBEEF00") ]
	(`evalStateT` ss) . runPipe $ fromHandleLike (SHandle h)
		=$= sasl d mechanisms
		=$= toHandleLike (SHandle h)
	(Just ns, _fts) <- runWriterT . runPipe $ fromHandleLike (WHandle h)
		=$= bind d rsc
		=@= toHandleLike (WHandle h)
	runPipe_ $ yield (Presence tagsNull []) =$= output =$= toHandleLike h
	let	r = fromHandleLike h =$= input ns
		w = output =$= toHandleLike h
	return $ Xmpp nr r w

presence :: Mpi
presence = Presence
	(tagsNull { tagFrom = Just $ Jid "yoshikuni" "localhost" Nothing }) []

fromHandleLike :: HandleLike h => h -> Pipe () BS.ByteString (HandleMonad h) ()
fromHandleLike h = lift (hlGetContent h) >>= yield >> fromHandleLike h

toHandleLike :: HandleLike h => h -> Pipe BS.ByteString () (HandleMonad h) ()
toHandleLike h = await >>= maybe (return ()) ((>> toHandleLike h) . lift . hlPut h)

{-
main_ :: IO ()
main_ = do
	(x :: Xml (ReadWrite Handle)) <- generate $ RW stdin stdout
	runPipe_ $ readFrom x =$= writeTo x
	-}

main :: IO ()
main = do
	h <- connectTo "localhost" $ PortNumber 5222
	(x :: Xmpp Handle) <- generate h
	forkIO . runPipe_ $ readFrom x
		=$= convert (BSC.pack . show)
		=$= toHandleLn stdout
	runPipe_ $ fromHandle stdin
		=$= xmlEvent
		=$= convert fromJust
		=$= xmlNode []
		=$= checkNothing
		=$= writeTo x

checkNothing :: Monad m => Pipe XmlNode (Maybe XmlNode) m ()
checkNothing = (await >>=) . maybe (return ()) $ \n -> case n of
	XmlNode (_, "nothing") [] [] [] -> yield Nothing >> checkNothing
	_ -> yield (Just n) >> checkNothing

addRandom :: (MonadBase IO m, Random r) => Pipe a (a, r) m ()
addRandom = (await >>=) . maybe (return ()) $ \x -> do
	r <- lift $ liftBase randomIO
	yield (x, r)
	addRandom

toResponse :: Maybe XmlNode -> Maybe BS.ByteString -> Maybe Mpi
toResponse mn (Just i) = case mn of
	Just n -> Just $ Iq (tagsType "result") {
			tagId = Just i,
			tagTo = Just $
				Jid "yoshio" "localhost" (Just "profanity") } [n]
	_ -> Just $ Iq (tagsType "result") {
			tagId = Just i,
			tagTo = Just $
				Jid "yoshio" "localhost" (Just "profanity") } []
toResponse mn _ = toMessage <$> mn

toIq :: XmlNode -> Int -> Mpi
toIq n r = Iq (tagsType "get") {
	tagId = Just . BSC.pack $ show r,
	tagTo = Just $ Jid "yoshio" "localhost" (Just "profanity") } [n]

toMessage :: XmlNode -> Mpi
toMessage n = Message (tagsType "chat") {
	tagId = Just "hoge",
	tagTo = Just $ Jid "yoshio" "localhost" Nothing } [n]

mkMessage :: BS.ByteString -> Mpi
mkMessage m = Message
	(tagsType "chat") {
		tagId = Just "hoge",
		tagTo = Just $ Jid "yoshio" "localhost" Nothing }
	[XmlNode (nullQ "body") [] [] [XmlCharData m]]

fromMessage :: Mpi -> Maybe XmlNode
fromMessage (Message ts [n]) = Just n
fromMessage (Iq ts [n]) = Just n
fromMessage _ = Nothing

data ReadWrite h = RW h h deriving Show

instance HandleLike h => HandleLike (ReadWrite h) where
	type HandleMonad (ReadWrite h) = HandleMonad h
	hlPut (RW _ w) = hlPut w
	hlGet (RW r _) = hlGet r
	hlClose (RW r w) = hlClose r >> hlClose w

data St = St [(BS.ByteString, BS.ByteString)]
instance SaslState St where getSaslState (St ss) = ss; putSaslState ss _ = St ss

mechanisms :: [BS.ByteString]
mechanisms = ["SCRAM-SHA-1", "DIGEST-MD5", "PLAIN"]

data SHandle s h = SHandle h deriving Show

instance HandleLike h => HandleLike (SHandle s h) where
	type HandleMonad (SHandle s h) = StateT s (HandleMonad h)
	hlPut (SHandle h) = lift . hlPut h
	hlGet (SHandle h) = lift . hlGet h
	hlClose (SHandle h) = lift $ hlClose h

data WHandle w h = WHandle h deriving Show

instance (HandleLike h, Monoid w) => HandleLike (WHandle w h) where
	type HandleMonad (WHandle w h) = WriterT w (HandleMonad h)
	hlPut (WHandle h) = lift . hlPut h
	hlGet (WHandle h) = lift . hlGet h
	hlClose (WHandle h) = lift $ hlClose h
