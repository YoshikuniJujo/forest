{-# LANGUAGE OverloadedStrings, FlexibleContexts, PackageImports #-}

import Control.Applicative
import Control.Arrow
import Control.Monad
import "monads-tf" Control.Monad.State
import "monads-tf" Control.Monad.Error
import Control.Concurrent hiding (yield)
import Control.Concurrent.STM
import Data.Pipe
import Data.Pipe.IO (debug)
import Data.Pipe.ByteString
import Data.Pipe.TChan
import Network
import Network.Sasl
import Network.XMPiPe.Core.C2S.Server

import qualified Data.ByteString as BS
import qualified Network.Sasl.DigestMd5.Server as DM5
import qualified Network.Sasl.ScramSha1.Server as SS1

main :: IO ()
main = do
	userlist <- atomically $ newTVar []
	soc <- listenOn $ PortNumber 5222
	forever $ accept soc >>= \(h, _, _) -> forkIO $ do
		c <- atomically newTChan
		(Just ns, st) <- (`runStateT` initXSt) . runPipe $ do
			fromHandle h =$= sasl "localhost" retrieves =$= toHandle h
			fromHandle h =$= bind "localhost" [] =@= toHandle h
		let u = user st; sl = selector userlist
		atomically $ modifyTVar userlist ((u, c) :)
		void . forkIO . runPipe_ $ fromTChan c =$= output =$= toHandle h
		runPipe_ $ fromHandle h =$= input ns =$= debug =$= select u =$= toTChansM sl

selector :: TVar [(Jid, TChan Mpi)] -> IO [(Jid -> Bool, TChan Mpi)]
selector ul = map (first eq) <$> atomically (readTVar ul)
	where
	eq (Jid u d _) (Jid v e Nothing) = u == v && d == e
	eq j k = j == k

select :: Monad m => Jid -> Pipe Mpi (Jid, Mpi) m ()
select f = (await >>=) . maybe (return ()) $ \mpi -> case mpi of
	End -> yield (f, End)
	Message tgs@(Tags { tagTo = Just to }) b ->
		yield (to, Message tgs { tagFrom = Just f } b) >> select f
	Iq tgs@(Tags { tagTo = Just to }) b ->
		yield (to, Iq tgs { tagFrom = Just f } b) >> select f
	_ -> select f

initXSt :: XSt
initXSt = XSt {
	user = Jid "" "localhost" Nothing, rands = repeat "00DEADBEEF00",
	sSt = [	("realm", "localhost"), ("qop", "auth"), ("charset", "utf-8"),
		("algorithm", "md5-sess") ] }

retrieves :: (
	MonadState m, SaslState (StateType m),
	MonadError m, SaslError (ErrorType m) ) => [Retrieve m]
retrieves = [RTPlain retrievePln, RTDigestMd5 retrieveDM5, RTScramSha1 retrieveSS1]

retrievePln :: (
	MonadState m, SaslState (StateType m),
	MonadError m, SaslError (ErrorType m) ) =>
	BS.ByteString -> BS.ByteString -> BS.ByteString -> m ()
retrievePln "" "yoshikuni" "password" = return ()
retrievePln "" "yoshio" "password" = return ()
retrievePln _ _ _ = throwError $ fromSaslError NotAuthorized "auth failure"

retrieveDM5 :: (
	MonadState m, SaslState (StateType m),
	MonadError m, SaslError (ErrorType m) ) => BS.ByteString -> m BS.ByteString
retrieveDM5 "yoshikuni" = return $ DM5.mkStored "yoshikuni" "localhost" "password"
retrieveDM5 "yoshio" = return $ DM5.mkStored "yoshio" "localhost" "password"
retrieveDM5 _ = throwError $ fromSaslError NotAuthorized "auth failure"

retrieveSS1 :: (
	MonadState m, SaslState (StateType m),
	MonadError m, SaslError (ErrorType m) ) => BS.ByteString ->
	m (BS.ByteString, BS.ByteString, BS.ByteString, Int)
retrieveSS1 "yoshikuni" = return (slt, stk, svk, i)
	where slt = "pepper"; i = 4492; (stk, svk) = SS1.salt "password" slt i
retrieveSS1 "yoshio" = return (slt, stk, svk, i)
	where slt = "sugar"; i = 4492; (stk, svk) = SS1.salt "password" slt i
retrieveSS1 _ = throwError $ fromSaslError NotAuthorized "auth failure"

type Pairs a = [(a, a)]
data XSt = XSt { user :: Jid, rands :: [BS.ByteString], sSt :: Pairs BS.ByteString }

instance XmppState XSt where
	getXmppState xs = (user xs, rands xs)
	putXmppState (usr, rl) xs = xs { user = usr, rands = rl }

instance SaslState XSt where
	getSaslState XSt { user = Jid n _ _, rands = nnc : _, sSt = ss } =
		("username", n) : ("nonce", nnc) : ("snonce", nnc) : ss
	getSaslState _ = error "XSt.getSaslState: null random list"
	putSaslState ss xs@XSt { user = Jid _ d r, rands = _ : rs } =
		xs { user = Jid n d r, rands = rs, sSt = ss }
		where Just n = lookup "username" ss
	putSaslState _ _ = error "XSt.getSaslState: null random list"
