{-# LANGUAGE OverloadedStrings, TypeFamilies, ScopedTypeVariables,
	FlexibleContexts,
	UndecidableInstances, PackageImports #-}

module XmppTls (
	XmppTls, One(..),
	XmppArgs(..), TlsArgs(..), testPusher) where

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
import Data.X509
import Data.X509.CertificateStore
import System.Random
import Text.XML.Pipe
import Network.Sasl
import Network.XMPiPe.Core.C2S.Client
import Network.PeyoTLS.TChan.Client
import "crypto-random" Crypto.Random

import qualified Data.ByteString as BS

import XmlPusher

data XmppTls h = XmppTls
	(XmlNode -> Bool)
	(TChan (Maybe BS.ByteString))
	(Pipe () Mpi (HandleMonad h) ())
	(TChan (Either BS.ByteString XmlNode))

data XmppArgs = XmppArgs {
	mechanisms :: [BS.ByteString],
	wantResponse :: XmlNode -> Bool,
	iNeedResponse :: XmlNode -> Bool,
	myJid :: Jid,
	password :: BS.ByteString,
	yourJid :: Jid
	}

data TlsArgs = TlsArgs {
	certificateAuthority :: CertificateStore,
	keyChain :: [(CertSecretKey, CertificateChain)]
	}

instance XmlPusher XmppTls where
	type NumOfHandle XmppTls = One
	type PusherArg XmppTls = (XmppArgs, TlsArgs)
	generate = makeXmppTls
	readFrom (XmppTls wr nr r wc) = r
		=$= pushId wr nr wc
		=$= convert fromMessage
		=$= filter isJust
		=$= convert fromJust
	writeTo (XmppTls _ _nr _ w) = convert maybeToEither =$= toTChan w
	

maybeToEither :: a -> Either BS.ByteString a
maybeToEither x = Right x

pushId :: MonadBase IO m => (XmlNode -> Bool) -> TChan (Maybe BS.ByteString) ->
	TChan (Either BS.ByteString XmlNode) -> Pipe Mpi Mpi m ()
pushId wr nr wc = (await >>=) . maybe (return ()) $ \mpi -> case mpi of
	Iq Tags { tagType = Just "get", tagId = Just i } [n]
		| wr n -> do
			lift . liftBase . atomically . writeTChan nr $ Just i
			yield mpi >> pushId wr nr wc
		| otherwise -> do
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
	Pipe (Either BS.ByteString XmlNode, UUID) Mpi m ()
makeResponse inr you nr = (await >>=) . maybe (return ()) $ \(mn, r) -> do
	case mn of
		Left i | not $ BS.null i -> maybe (return ()) yield $
			toResponse you mn (Just i) undefined
		_ -> do	e <- lift . liftBase . atomically $ isEmptyTChan nr
			uuid <- lift $ liftBase randomIO
			if e
			then either (const $ return ())
				(yield . makeIqMessage inr you r uuid) mn
			else do	i <- lift . liftBase . atomically $ readTChan nr
				maybe (return ()) yield $ toResponse you mn i uuid
	makeResponse inr you nr

makeIqMessage :: (XmlNode -> Bool) -> Jid -> UUID -> UUID -> XmlNode -> Mpi
makeIqMessage inr you r uuid n =
	if inr n then toIq you n r else toMessage you n uuid

toResponse :: Jid -> Either BS.ByteString XmlNode ->
	Maybe BS.ByteString -> UUID -> Maybe Mpi
toResponse you mn (Just i) _ = case mn of
	Right n -> Just $
		Iq (tagsType "result") { tagId = Just i, tagTo = Just $ you } [n]
	_ -> Just $
		Iq (tagsType "result") { tagId = Just i, tagTo = Just you } []
toResponse you (Right n) _ uuid = Just $ flip (toMessage you) uuid n
toResponse _ _ _ _ = Nothing

toIq :: Jid -> XmlNode -> UUID -> Mpi
toIq you n r = Iq
	(tagsType "get") { tagId = Just $ toASCIIBytes r, tagTo = Just you } [n]

toMessage :: Jid -> XmlNode -> UUID -> Mpi
toMessage you n uuid = Message
	(tagsType "chat") { tagId = Just $ toASCIIBytes uuid, tagTo = Just you } [n]

makeXmppTls :: (
	ValidateHandle h, MonadBaseControl IO (HandleMonad h),
	MonadError (HandleMonad h), Error (ErrorType (HandleMonad h))
	) => One h -> (XmppArgs, TlsArgs) -> HandleMonad h (XmppTls h)
makeXmppTls (One h) (XmppArgs ms wr inr me ps you, TlsArgs ca kcs) = do
	nr <- liftBase $ atomically newTChan
	wc <- liftBase $ atomically newTChan
	(g :: SystemRNG) <- liftBase $ cprgCreate <$> createEntropyPool
	let	(Jid un d (Just rsc)) = me
		(cn, g') = cprgGenerate 32 g
		ss = St [
			("username", un), ("authcid", un), ("password", ps),
			("cnonce", cn) ]
	runPipe_ $ fromHandleLike h =$= starttls "localhost" =$= toHandleLike h
--	ca <- liftBase $ readCertificateStore ["certs/cacert.sample_pem"]
--	k <- liftBase $ readKey "certs/yoshikuni.sample_key"
--	c <- liftBase $ readCertificateChain ["certs/yoshikuni.sample_crt"]
	(inc, otc) <-
		open' h "localhost" ["TLS_RSA_WITH_AES_128_CBC_SHA"] kcs ca g'
	(`evalStateT` ss) . runPipe_ $ fromTChan inc =$= sasl d ms =$= toTChan otc
	(Just ns, _fts) <- runWriterT . runPipe $ fromTChan inc
		=$= bind d rsc
		=@= toTChan otc
	runPipe_ $ yield (Presence tagsNull []) =$= output =$= toTChan otc
	(>> return ()) . liftBaseDiscard forkIO . runPipe_ $ fromTChan wc
		=$= addRandom =$= makeResponse inr you nr =$= output =$= toTChan otc
	let	r = fromTChan inc =$= input ns
	return $ XmppTls wr nr r wc

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
