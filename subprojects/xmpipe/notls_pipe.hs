{-# LANGUAGE OverloadedStrings, TypeFamilies, PackageImports, FlexibleContexts #-}

import Debug.Trace

import "monads-tf" Control.Monad.State
import Data.List
import Data.Pipe
import Data.HandleLike
import System.Environment
import System.IO.Unsafe
import Network

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

import XmppClient
import Caps (profanityCaps)

main :: IO ()
main = connectTo "localhost" (PortNumber 5222) >>= \h ->
	xmpp (SHandle h) `evalStateT` ("" :: BS.ByteString)

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
	Just (SRFeatures [Mechanisms ms])
		| DigestMd5 `elem` ms -> digestMd5 sender >> process
	Just SRSaslSuccess -> mapM_ yield [SRXmlDecl, begin] >> process
	Just (SRFeatures fs) -> do
		trace "HERE" (return ())
		let Just Caps { cnode = n, cver = v } = find isCaps fs
		trace (show $ (n, v)) (return ())
		mapM_ yield binds
--		yield $ getCaps "prof_caps_4492" Nothing v n
		process
	Just (SRPresence _ (C [(CTHash, "sha-1"), (CTVer, v), (CTNode, n)])) -> do
		yield (getCaps "prof_caps_2"
			(Just . Jid sender  "localhost" $ Just "profanity") v n)
		process
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

getCaps :: BS.ByteString -> Maybe Jid -> BS.ByteString -> BS.ByteString ->
	Common
getCaps i (Just t) v n = SRIq Get i Nothing (Just t) $ IqCapsQuery v n
getCaps i _ v n = SRIq Get i Nothing Nothing $ IqCapsQuery v n

resultCaps :: BS.ByteString -> Jid -> BS.ByteString -> Common
resultCaps i t n =
	SRIq Result i Nothing (Just t) (IqCapsQuery2 profanityCaps n)

sender, message :: BS.ByteString
recipient :: Jid
(sender, recipient, message) = unsafePerformIO $ do
	[s, r, m] <- getArgs
	return (BSC.pack s, Jid (BSC.pack r) "localhost" Nothing, BSC.pack m)
