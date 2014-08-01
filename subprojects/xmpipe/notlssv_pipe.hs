{-# LANGUAGE OverloadedStrings, TypeFamilies, TupleSections, FlexibleContexts,
	PackageImports #-}

import Data.UUID
import System.Random

import Control.Applicative
import Control.Monad
import "monads-tf" Control.Monad.State
import Control.Concurrent (forkIO)
import Data.Pipe
import Data.HandleLike
import Text.XML.Pipe
import Network

import XmppServer

data SHandle s h = SHandle h

instance HandleLike h => HandleLike (SHandle s h) where
	type HandleMonad (SHandle s h) = StateT s (HandleMonad h)
	type DebugLevel (SHandle s h) = DebugLevel h
	hlPut (SHandle h) = lift . hlPut h
	hlGet (SHandle h) = lift . hlGet h
	hlClose (SHandle h) = lift $ hlClose h
	hlDebug (SHandle h) = (lift .) . hlDebug h

main :: IO ()
main = do
	socket <- listenOn $ PortNumber 5222
	forever $ do
		(h, _, _) <- accept socket
		uuids <- randoms <$> getStdGen
		voidM . forkIO . (`evalStateT` initXmppState uuids)
			. xmpp $ SHandle h

xmpp :: (MonadState (HandleMonad h), StateType (HandleMonad h) ~ XmppState,
		HandleLike h) => h -> HandleMonad h ()
xmpp h = do
	voidM . runPipe $ input h =$= makeP =$= output h
	hlPut h $ xmlString [XmlEnd (("stream", Nothing), "stream")]
	hlClose h

makeP :: (MonadState m, StateType m ~ XmppState) =>
	Pipe ShowResponse ShowResponse m ()
makeP = (,) `liftM` await `ap` lift (gets receiver) >>= \p -> case p of
	(Just (SRCommon (SRStream _)), Nothing) -> do
		yield $ SRCommon SRXmlDecl
		lift nextUuid >>= \u -> yield . SRCommon $ SRStream [
			(Id, toASCIIBytes u),
			(From, "localhost"), (Version, "1.0"), (Lang, "en") ]
		lift nextUuid >>= digestMd5 >>= \un -> lift . modify .
			setReceiver $ Jid un "localhost" Nothing
		makeP
	(Just (SRCommon (SRStream _)), _) -> do
		yield $ SRCommon SRXmlDecl
		lift nextUuid >>= \u -> yield . SRCommon $ SRStream [
			(Id, toASCIIBytes u),
			(From, "localhost"), (Version, "1.0"), (Lang, "en") ]
		yield . SRCommon $ SRFeatures
			[Rosterver Optional, Bind Required, Session Optional]
		makeP
	(Just (SRIq Set i Nothing Nothing
		(IqBind (Just Required) (Resource n))), _) -> do
		lift $ modify (setResource n)
		Just j <- lift $ gets receiver
		yield . SRIq Result i Nothing Nothing
			. IqBind Nothing $ BJid j
		makeP
	(Just (SRIq Set i Nothing Nothing IqSession), mrcv) ->
		yield (SRIq Result i Nothing mrcv IqSessionNull) >> makeP
	(Just (SRIq Get i Nothing Nothing (IqRoster Nothing)), mrcv) -> do
		yield . SRIq Result i Nothing mrcv
			. IqRoster . Just $ Roster (Just "1") []
		makeP
	(Just (SRPresence _ _), Just rcv) ->
		yield (SRMessage Chat "hoge" sender rcv message) >> makeP
	_ -> return ()

voidM :: Monad m => m a -> m ()
voidM = (>> return ())

sender :: Jid
sender = Jid "yoshio" "localhost" (Just "profanity")

message :: [XmlNode]
message = [XmlNode (("", Nothing), "body") [] [] [XmlCharData "Hi!"]]
