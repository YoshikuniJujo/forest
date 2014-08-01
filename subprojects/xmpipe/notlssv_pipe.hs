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

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

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

checkP :: (HandleLike h, Show a) => h -> Pipe a a (HandleMonad h) ()
checkP h = do
	mx <- await
	case mx of
		Just x -> do
			lift . hlDebug h "critical" . BSC.pack . (++ "\n") $ show x
			yield x
			checkP h
		_ -> return ()

sender, receiver, receiver' :: Jid
sender = Jid "yoshio" "localhost" (Just "profanity")
receiver = Jid "yoshikuni" "localhost" Nothing
receiver' = Jid "yoshikuni" "localhost" (Just "profanity")

makeSR :: (Int, UUID) -> ShowResponse -> [ShowResponse]
makeSR (0, u) (SRStream _) = [
	SRXmlDecl,
	SRStream [
		(Id, toASCIIBytes u),
		(From, "localhost"), (Version, "1.0"), (Lang, "en")] ]
makeSR (1, u) (SRStream _) = [
	SRXmlDecl,
	SRStream [
		(Id, toASCIIBytes u),
		(From, "localhost"), (Version, "1.0"), (Lang, "en")],
	SRFeatures [Rosterver Optional, Bind Required, Session Optional] ]
makeSR _ (SRAuth _) = error "makeR: not implemented auth mechanism"
makeSR _ (SRStream _) = error "makeR: not implemented"
makeSR _ (SRIq [(Id, i), (Type, "set")] [IqBindReq Required (Resource _n)]) =
	(: []) $ SRIqRaw Result i Nothing Nothing $ JidResult receiver'
makeSR _ (SRIq [(Id, i), (Type, "set")] [IqSession]) = 
	[SRIqRaw Result i Nothing (Just receiver') QueryNull]
makeSR _ (SRIq [(Id, i), (Type, "get")] [IqRoster]) =
	(: []) $ SRIqRaw Result i Nothing (Just receiver') $ RosterResult "1" []
makeSR _ (SRPresence _ _) = (: []) $ SRMessage Chat "hoge" sender receiver
		[XmlNode (nullQ "body") [] [] [XmlCharData "Hogeru"]]
makeSR _ _ = []

makeP :: (MonadState m, StateType m ~ XmppState) =>
	Pipe ShowResponse ShowResponse m ()
makeP = do
	n <- lift $ gets sequenceNumber
	mr <- await
	case mr of
		Just r@(SRStream _) -> do
			lift . modify $ modifySequenceNumber (+ 1)
			u <- lift nextUuid
			mapM_ yield $ makeSR (n, u) r
			when (n == 0) $ digestMd5 u
			makeP
		Just r -> do
			u <- lift nextUuid
			mapM_ yield $ makeSR (n, u) r
			makeP
		_ -> return ()

handleP :: HandleLike h => h -> Pipe () BS.ByteString (HandleMonad h) ()
handleP h = do
	c <- lift $ hlGetContent h
	yield c
	handleP h

voidM :: Monad m => m a -> m ()
voidM = (>> return ())

nullQ :: BS.ByteString -> QName
nullQ = (("", Nothing) ,)
