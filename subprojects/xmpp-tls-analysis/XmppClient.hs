{-# LANGUAGE OverloadedStrings #-}

module XmppClient (connectSendMsg, connectSendIq) where

import Prelude hiding (drop, filter)

import Control.Monad.IO.Class
import Control.Monad.Catch
import Data.Conduit
import Data.Conduit.List
import qualified Data.Conduit.List as Cd
import Text.XML.Stream.Parse

import EventToElement
import XmppTypes
import Data.XML.Types

import qualified Data.ByteString as BS
import qualified Data.Text as T

import HandleLike

connect :: HandleLike h => h -> IO ()
connect sv = do
	hlPut sv $ beginDoc +++ stream
	ioSource (hlGetContent sv)
		=$= parseBytes def
		=$= eventToElementAll
		=$= Cd.map elementToStanza
		=$= runIO (responseToServer sv "")
		=$= runIO (putStrLn . (color 31 "S: " ++) . show)
		$$ sinkNull
	putStrLn "connected"

stanzaSource :: (Monad m, MonadIO m, MonadThrow m) =>
	HandleLike h => h -> Source m Stanza
stanzaSource sv = ioSource (hlGetContent sv)
	=$= parseBytes def
	=$= eventToElementAll
	=$= Cd.map elementToStanza

connectSendMsg :: HandleLike h => h -> T.Text -> IO ()
connectSendMsg sv msg = do
	hlPut sv $ beginDoc +++ stream
	ioSource (hlGetContent sv)
		=$= parseBytes def
		=$= checkEnd sv
		=$= eventToElementAll
		=$= myMap elementToStanza
		=$= runIO (responseToServer sv msg)
		=$= runIO (putStrLn . (color 31 "S: " ++) . show)
		$$ mySink
	putStrLn "Finished"

myMap :: Monad m => (a -> b) -> Conduit a m b
myMap f = do
	mx <- await
	case mx of
		Just x -> do
			yield $ f x
			myMap f
		_ -> return ()

mySink :: Monad m => Sink Stanza m ()
mySink = do
	ms <- await
	case ms of
		Just (StanzaIq { iqId = "_xmpp_session1" }) -> return ()
		Nothing -> return ()
		_ -> mySink
-- responseToServer sv msg (StanzaIq { iqId = "_xmpp_session1" }) = do

checkEnd :: HandleLike h => h -> Conduit Event IO Event
checkEnd h = do
	me <- await
	liftIO $ print me
	case me of
		Just (EventEndElement (Name "stream" _ _)) -> do
			liftIO $ do
				putStrLn "End stream"
--				exitSuccess
			return ()
		Just e -> do
			yield e
			checkEnd h
		_ -> return ()

connectSendIq :: HandleLike h => h -> Element -> IO ()
connectSendIq sv msg = do
	hlPut sv $ beginDoc +++ stream
	ioSource (hlGetContent sv)
		=$= parseBytes def
		=$= eventToElementAll
		=$= Cd.map elementToStanza
		=$= runIO (responseToServer' sv $ makeIq msg)
		=$= runIO (putStrLn . (color 31 "S: " ++) . show)
		$$ sinkNull
	putStrLn "Finished"

ioSource :: MonadIO m => IO a -> Source m a
ioSource io = do
	x <- liftIO io
	yield x
	ioSource io

sinkOnce :: (Monad m, MonadIO m, Show a) => Sink a m ()
sinkOnce = do
	x <- await
	liftIO $ print x

conduitOnce :: (Monad m, MonadIO m, Show a) => Conduit a m a
conduitOnce = do
 	mx <- await
	case mx of
		Just x -> yield x
		_ -> return ()
	

responseToServer :: HandleLike h => h -> T.Text -> Stanza -> IO ()
responseToServer sv _ (StanzaMechanismList ms)
	| DigestMd5 `elem` ms = hlPut sv . showElement . stanzaToElement $
		StanzaMechanism DigestMd5
	| otherwise = error "responseToServer: Server has no DIGEST-MD5"
responseToServer sv _ (StanzaChallenge ch@(Challenge {})) = let
	rlm = realm ch
	nnc = nonce ch
	qp = qop ch
	cs = charset ch
	alg = algorithm ch in case (qp, cs, alg) of
		("auth", "utf-8", "md5-sess") -> hlPut sv . showElement .
			stanzaToElement $ StanzaResponse Response {
				rUsername = "yoshikuni",
				rRealm = rlm,
				rPassword = "password",
				rCnonce = "00EADBEEF00",
				rNonce = nnc,
				rNc = "00000001",
				rQop = qp,
				rDigestUri = "xmpp/localhost",
				rCharset = cs
			 }
		_ -> error "responseToServer: not implemented"
responseToServer sv _ (StanzaChallenge (ChallengeRspauth _)) =
	hlPut sv . showElement . stanzaToElement $ StanzaResponse ResponseNull
responseToServer sv _ StanzaSuccess = hlPut sv $ beginDoc +++ stream
responseToServer sv _ (StanzaFeatureList fl)
	| FeatureBind Required `elem` fl = hlPut sv . showElement . stanzaToElement $
		StanzaIq {
			iqId = "_xmpp_bind1",
			iqType = IqSet,
			iqTo = Nothing,
			iqBody = IqBodyBind [Required, BindResource "profanity"]
		 }
responseToServer sv _ (StanzaIq { iqId = "_xmpp_bind1" }) =
	hlPut sv . showElement . stanzaToElement $ StanzaIq {
		iqId = "_xmpp_session1",
		iqType = IqSet,
		iqTo = Nothing,
		iqBody = IqBodySession
	 }
responseToServer sv msg (StanzaIq { iqId = "_xmpp_session1" }) = do
	BS.putStrLn "\n##### HERE ####\n"
	BS.putStr . showElement . stanzaToElement $ StanzaMessage {
		messageType = "chat",
		messageId = "yoshikuni1",
		messageFrom = Nothing,
		messageTo = Just "yoshio@localhost",
		messageBody = [NodeElement $
			Element (Name "body" (Just "jabber:client") Nothing) [] [
				NodeContent $ ContentText ("message: " `T.append` msg)
			 ]
		 ]
	 }
	hlPut sv . showElement . stanzaToElement $ StanzaMessage {
		messageType = "chat",
		messageId = "yoshikuni1",
		messageFrom = Nothing,
		messageTo = Just "yoshio@localhost",
		messageBody = [NodeElement $
			Element (Name "body" (Just "jabber:client") Nothing) [] [
				NodeContent $ ContentText ("message: " `T.append` msg)
			 ]
		 ]
	 }
	hlPut sv "<presence/>"
--	hlPut sv "</stream:stream>"
responseToServer _ _ _ = return ()

beginDoc, stream :: BS.ByteString
beginDoc = "<?xml version=\"1.0\"?>"
stream = "<stream:stream to=\"localhost\" xml:lang=\"en\" version=\"1.0\" " +++
	"xmlns=\"jabber:client\" " +++
	"xmlns:stream=\"http://etherx.jabber.org/streams\">"

runIO :: (Monad m, MonadIO m) => (a -> IO ()) -> Conduit a m a
runIO io = do
	mx <- await
	maybe (return ()) (\x -> liftIO (io x) >> yield x) mx
	runIO io

color :: Int -> String -> String
color clr str = "\x1b[" ++ show clr ++ "m" ++ str ++ "\x1b[39m"

(+++) :: BS.ByteString -> BS.ByteString -> BS.ByteString
(+++) = BS.append

makeIq :: Element -> Stanza
makeIq msg = StanzaIq {
	iqId = "hogeru",
	iqType = IqGet,
	iqTo = Just "yoshio@localhost",
	iqBody = IqBodyRaw msg
 }

responseToServer' :: HandleLike h => h -> Stanza -> Stanza -> IO ()
responseToServer' sv _ (StanzaMechanismList ms)
	| DigestMd5 `elem` ms = hlPut sv . showElement . stanzaToElement $
		StanzaMechanism DigestMd5
	| otherwise = error "responseToServer: Server has no DIGEST-MD5"
responseToServer' sv _ (StanzaChallenge ch@(Challenge {})) = let
	rlm = realm ch
	nnc = nonce ch
	qp = qop ch
	cs = charset ch
	alg = algorithm ch in case (qp, cs, alg) of
		("auth", "utf-8", "md5-sess") -> hlPut sv . showElement .
			stanzaToElement $ StanzaResponse Response {
				rUsername = "yoshikuni",
				rRealm = rlm,
				rPassword = "password",
				rCnonce = "00EADBEEF00",
				rNonce = nnc,
				rNc = "00000001",
				rQop = qp,
				rDigestUri = "xmpp/localhost",
				rCharset = cs
			 }
		_ -> error "responseToServer': not implemented"
responseToServer' sv _ (StanzaChallenge (ChallengeRspauth _)) =
	hlPut sv . showElement . stanzaToElement $ StanzaResponse ResponseNull
responseToServer' sv _ StanzaSuccess = hlPut sv $ beginDoc +++ stream
responseToServer' sv _ (StanzaFeatureList fl)
	| FeatureBind Required `elem` fl = hlPut sv . showElement . stanzaToElement $
		StanzaIq {
			iqId = "_xmpp_bind1",
			iqType = IqSet,
			iqTo = Nothing,
			iqBody = IqBodyBind [Required, BindResource "profanity"]
		 }
responseToServer' sv _ (StanzaIq { iqId = "_xmpp_bind1" }) =
	hlPut sv . showElement . stanzaToElement $ StanzaIq {
		iqId = "_xmpp_session1",
		iqType = IqSet,
		iqTo = Nothing,
		iqBody = IqBodySession
	 }
responseToServer' sv msg (StanzaIq { iqId = "_xmpp_session1" }) = do
	BS.putStrLn ""
	BS.putStr . showElement $ stanzaToElement msg
	BS.putStrLn ""
	hlPut sv . showElement $ stanzaToElement msg
	hlPut sv "</stream:stream>"
responseToServer' _ _ _ = return ()
