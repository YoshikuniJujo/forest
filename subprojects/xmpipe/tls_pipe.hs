{-# LANGUAGE OverloadedStrings, TypeFamilies, PackageImports, FlexibleContexts #-}

import Control.Applicative
import "monads-tf" Control.Monad.State
import Data.Maybe
import Data.Pipe
import Data.HandleLike
import System.Environment
import System.IO.Unsafe
import Network
import Network.PeyoTLS.Client
import Network.PeyoTLS.ReadFile
import "crypto-random" Crypto.Random

import Text.XML.Pipe

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

import XmppClient
import Caps (profanityCaps)

main :: IO ()
main = do
	h <- connectTo "localhost" (PortNumber 5222)
	void . runPipe $ (yield begin >> yield startTls) =$= output h
	void . runPipe $ handleP h
		=$= xmlEvent
		=$= convert fromJust
		=$= (xmlBegin >>= xmlNodeUntil isProceed)
		=$= awaitAll
	ca <- readCertificateStore ["cacert.sample_pem"]
	g <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	(`run` g) $ do
		p <- open' h "localhost" ["TLS_RSA_WITH_AES_128_CBC_SHA"] [] ca
		xmpp (SHandle p) `evalStateT` ("" :: BS.ByteString)

pipe :: Monad m => Pipe a a m ()
pipe = await >>= maybe (return ()) yield

awaitAll :: Monad m => Pipe a () m ()
awaitAll = await >>= maybe (return ()) (const awaitAll)

startTls :: ShowResponse
startTls = SRRaw $ XmlNode (("", Nothing), "starttls")
	[("", "urn:ietf:params:xml:ns:xmpp-tls")] [] []

xmpp :: (HandleLike h, MonadState (HandleMonad h),
		BS.ByteString ~ StateType (HandleMonad h)) => h -> HandleMonad h ()
xmpp h = voidM . runPipe $ input h =$= proc =$= output h

proc :: (Monad m, MonadState m, StateType m ~ BS.ByteString) =>
	Pipe ShowResponse ShowResponse m ()
proc = yield (SRCommon SRXmlDecl)
	>> yield (SRCommon $
		SRStream [(To, "localhost"), (Version, "1.0"), (Lang, "en")])
	>> process

process :: (Monad m, MonadState m, StateType m ~ BS.ByteString) =>
	Pipe ShowResponse ShowResponse m ()
process = await >>= \mr -> case mr of
	Just (SRCommon (SRFeatures [_, Mechanisms ms]))
		| DigestMd5 `elem` ms -> digestMd5 sender >> process
	Just SRSaslSuccess -> mapM_ yield [SRCommon SRXmlDecl, begin] >> process
	Just (SRCommon (SRFeatures fs)) -> mapM_ yield binds >> process
	Just (SRPresence _ (C [(CTHash, "sha-1"), (CTVer, v), (CTNode, n)]))
		-> yield (getCaps v n) >> process
	Just (SRIq Get i [(IqTo, to), (IqFrom, f)] (IqDiscoInfoNode [(DTNode, n)]))
		| to == sender `BS.append` "@localhost/profanity" -> do
			yield $ resultCaps i f n
			yield $ SRMessageRaw Chat "prof_3" recipient message
			yield SREnd
	Just _ -> process
	_ -> return ()

begin :: ShowResponse
begin = SRCommon $ SRStream [(To, "localhost"), (Version, "1.0"), (Lang, "en")]

binds :: [ShowResponse]
binds = [
	SRIq Set "_xmpp_bind1" [] . IqBind $ Resource "profanity",
	SRIq Set "_xmpp_session1" [] IqSession,
	SRIq Get "_xmpp_roster1" [] $ IqRoster [],
	SRPresenceRaw "prof_presence_1" "http://www.profanity.im" profanityCaps ]

getCaps :: BS.ByteString -> BS.ByteString -> ShowResponse
getCaps v n = SRIq Get "prof_caps_2" [
	(IqTo, sender `BS.append` "@localhost/profanity") ] $ IqCapsQuery v n

resultCaps :: BS.ByteString -> BS.ByteString -> BS.ByteString -> ShowResponse
resultCaps i t n = SRIq Result i [(IqTo, t)] (IqCapsQuery2 profanityCaps n)

sender, message :: BS.ByteString
recipient :: Jid
(sender, recipient, message) = unsafePerformIO $ do
	[s, r, m] <- getArgs
	return (BSC.pack s, Jid (BSC.pack r) "localhost" Nothing, BSC.pack m)

isProceed :: XmlNode -> Bool
isProceed (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-tls"), "proceed") _ [] [])
	= True
isProceed _ = False
