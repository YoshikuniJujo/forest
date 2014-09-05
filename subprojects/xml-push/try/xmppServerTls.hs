{-# LANGUAGE OverloadedStrings, FlexibleContexts,
	PackageImports #-}

import Control.Applicative
import Control.Arrow
import Control.Monad
import "monads-tf" Control.Monad.State
import "monads-tf" Control.Monad.Error
import Control.Monad.Trans.Control
import Control.Concurrent hiding (yield)
import Control.Concurrent.STM
import Data.Pipe
import Data.Pipe.IO (debug)
import Data.Pipe.ByteString
import Data.Pipe.TChan
import Data.Char
import Data.UUID
import System.Random
import Network
import Network.Sasl
import Network.XMPiPe.Core.C2S.Server
import Network.PeyoTLS.ReadFile
import Network.PeyoTLS.TChan.Server
import "crypto-random" Crypto.Random

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Network.Sasl.ScramSha1.Server as SS1
import qualified Network.Sasl.DigestMd5.Server as DM5

main :: IO ()
main = do
	userlist <- atomically $ newTVar []
	soc <- listenOn $ PortNumber 5222
	ca <- readCertificateStore ["certs/cacert.sample_pem"]
	k <- readKey "certs/localhost.sample_key"
	c <- readCertificateChain ["certs/localhost.sample_crt"]
	g0 <- cprgCreate <$> createEntropyPool :: IO SystemRNG
	(`evalStateT` g0) . forever $ lift (accept soc) >>= \(h, _, _) -> liftBaseDiscard forkIO $ do
		g <- StateT $ return . cprgFork
		ch <- lift $ atomically newTChan
		us <- map toASCIIBytes . randoms <$> lift getStdGen
		_us' <- (`execStateT` us) . runPipe $
			fromHandle h =$= starttls "localhost" =$= toHandle h
		(Just cn, (inp, otp)) <- lift $
			open h ["TLS_RSA_WITH_AES_128_CBC_SHA"] [(k, c)] (Just ca) g
		lift . print $ cn "Yoshikuni"
		lift . print $ cn "Yoshio"
		let ck nm = cn (capitalize nm) || nm == "yoshio"
		(Just ns, st) <- (`runStateT` initXSt) . runPipe $ do
			fromTChan inp
				=$= debug
				=$= sasl "localhost" (retrieves ck)
				=$= toTChan otp
			fromTChan inp =$= bind "localhost" [] =@= toTChan otp
		let u = user st; sl = selector userlist
		lift . atomically $ modifyTVar userlist ((u, ch) :)
		void . liftBaseDiscard forkIO . runPipe_ $ fromTChan ch =$= output =$= toTChan otp
		lift . runPipe_ $ fromTChan inp =$= debug =$= input ns =$= select u =$= toTChansM sl

capitalize :: String -> String
capitalize (c : cs) = toUpper c : cs
capitalize "" = ""

initXSt :: XSt
initXSt = XSt {
	user = Jid "" "localhost" Nothing, rands = repeat "00DEADBEEF00",
	sSt = [ ("realm", "localhost"), ("qop", "auth"), ("charset", "utf-8"),
		("algorithm", "md5-sess") ] }

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

selector :: TVar [(Jid, TChan Mpi)] -> IO [(Jid -> Bool, TChan Mpi)]
selector ul = map (first eq) <$> atomically (readTVar ul)
	where
	eq (Jid u d _) (Jid v e Nothing) = u == v && d == e
	eq j k = j == k

select :: Monad m => Jid -> Pipe Mpi (Jid, Mpi) m ()
select f = (await >>=) . maybe (return ()) $ \mpi -> case mpi of
	End -> yield (f, End)
	Message tgs@Tags { tagTo = Just to } b ->
		yield (to, Message tgs { tagFrom = Just f } b) >> select f
	Iq tgs@Tags { tagTo = Just to } b ->
		yield (to, Iq tgs { tagFrom = Just f } b) >> select f
	_ -> select f

retrieves :: (MonadError m, SaslError (ErrorType m)) =>
	(String -> Bool) -> [Retrieve m]
retrieves ck = [
	RTScramSha1 retrieveSS1,
	RTDigestMd5 retrieveDM5,
	RTExternal $ retrieveExternal ck]

retrieveSS1 :: (MonadError m, SaslError (ErrorType m)) =>
	BS.ByteString -> m (BS.ByteString, BS.ByteString, BS.ByteString, Int)
retrieveSS1 "yoshikuni" = return (slt, stk, svk, i)
	where slt = "pepper"; i = 4492; (stk, svk) = SS1.salt "password" slt i
retrieveSS1 "yoshio" = return (slt, stk, svk, i)
	where slt = "sugar"; i = 4492; (stk, svk) = SS1.salt "password" slt i
retrieveSS1 _ = throwError $ fromSaslError NotAuthorized "bad"

retrieveDM5 :: (MonadError m, SaslError (ErrorType m)) =>
	BS.ByteString -> m BS.ByteString
retrieveDM5 "yoshikuni" = return $ DM5.mkStored "yoshikuni" "localhost" "password"
retrieveDM5 "yoshio" = return $ DM5.mkStored "yoshio" "localhost" "password"
retrieveDM5 _ = throwError $ fromSaslError NotAuthorized "auth failure"

retrieveExternal :: (MonadError m, SaslError (ErrorType m)) =>
	(String -> Bool) -> BS.ByteString -> m ()
retrieveExternal ck nm = if ck $ BSC.unpack nm then return () else
	throwError $ fromSaslError NotAuthorized "auth failure"
