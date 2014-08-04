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

startTls :: Common
startTls = SRRaw $ XmlNode (("", Nothing), "starttls")
	[("", "urn:ietf:params:xml:ns:xmpp-tls")] [] []

xmpp :: (HandleLike h, MonadState (HandleMonad h),
		BS.ByteString ~ StateType (HandleMonad h)) => h -> HandleMonad h ()
xmpp h = voidM . runPipe $ input h =$= proc =$= output h

proc :: (Monad m, MonadState m, StateType m ~ BS.ByteString) =>
	Pipe Common Common m ()
proc = yield SRXmlDecl
	>> yield (SRStream [(To, "localhost"), (Version, "1.0"), (Lang, "en")])
	>> process

process :: (Monad m, MonadState m, StateType m ~ BS.ByteString) =>
	Pipe Common Common m ()
process = await >>= \mr -> case mr of
	Just (SRFeatures [_, Mechanisms ms])
		| DigestMd5 `elem` ms -> digestMd5 sender >> process
	Just (SRFeatures [Mechanisms ms, _])
		| DigestMd5 `elem` ms -> digestMd5 sender >> process
	Just SRSaslSuccess -> mapM_ yield [SRXmlDecl, begin] >> process
	Just (SRFeatures fs) -> mapM_ yield binds >> process
	Just (SRPresence _ (C [(CTHash, "sha-1"), (CTVer, v), (CTNode, n)]))
		-> yield (getCaps v n) >> process
	Just (SRIq Get i (Just f) (Just to) (IqDiscoInfoNode [(DTNode, n)]))
		| to == Jid sender "localhost" (Just "profanity") -> do
			yield $ resultCaps i f n
			yield . SRMessage Chat "prof_3" Nothing recipient .
				MBody $ MessageBody message
			yield SREnd
	Just _ -> process
	_ -> return ()

begin :: Common
begin = SRStream [(To, "localhost"), (Version, "1.0"), (Lang, "en")]

binds :: [Common]
binds = [SRIq Set "_xmpp_bind1" Nothing Nothing . IqBind Nothing $
		Resource "profanity",
	SRIq Set "_xmpp_session1" Nothing Nothing IqSession,
	SRIq Get "_xmpp_roster1" Nothing Nothing $ IqRoster Nothing,
	SRPresence [(Id, "prof_presence_1")] $
		capsToCaps profanityCaps "http://www.profanity.im" ]

getCaps :: BS.ByteString -> BS.ByteString -> Common
getCaps v n = SRIq Get "prof_caps_2" Nothing
	(Just . Jid sender "localhost" $ Just "profanity") $
	IqCapsQuery v n

resultCaps :: BS.ByteString -> Jid -> BS.ByteString -> Common
resultCaps i t n =
	SRIq Result i Nothing (Just t) (IqCapsQuery2 profanityCaps n)

sender, message :: BS.ByteString
recipient :: Jid
(sender, recipient, message) = unsafePerformIO $ do
	[s, r, m] <- getArgs
	return (BSC.pack s, Jid (BSC.pack r) "localhost" Nothing, BSC.pack m)

isProceed :: XmlNode -> Bool
isProceed (XmlNode ((_, Just "urn:ietf:params:xml:ns:xmpp-tls"), "proceed") _ [] [])
	= True
isProceed _ = False
