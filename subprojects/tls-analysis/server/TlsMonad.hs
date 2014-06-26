{-# LANGUAGE PackageImports #-}

module TlsMonad (
	TlsM, evalTlsM, CS.initState,
		thlGet, thlPut, thlClose, thlDebug, thlError,
		withRandom, randomByteString, getBuf, setBuf, getWBuf, setWBuf,
		getClientSn, getServerSn, succClientSn, succServerSn,
	CS.Alert(..), CS.AlertLevel(..), CS.AlertDesc(..),
	CS.ContentType(..),
	CS.CipherSuite(..), CS.KeyExchange(..), CS.BulkEncryption(..),
	CS.ClientId, CS.newClientId, CS.Keys(..), CS.nullKeys ) where

import Control.Monad (liftM)
import "monads-tf" Control.Monad.Trans (lift)
import "monads-tf" Control.Monad.State (StateT, evalStateT, gets, modify)
import "monads-tf" Control.Monad.Error (ErrorT, runErrorT)
import Data.Word (Word64)
import Data.HandleLike (HandleLike(..))
import "crypto-random" Crypto.Random (CPRG, cprgGenerate)

import qualified Data.ByteString as BS

import qualified ClientState as CS (
	HandshakeState, initState, ClientId, newClientId, Keys(..), nullKeys,
	ContentType(..), Alert(..), AlertLevel(..), AlertDesc(..),
	CipherSuite(..), KeyExchange(..), BulkEncryption(..),
	randomGen, setRandomGen,
	setBuf, getBuf, setWBuf, getWBuf,
	getClientSN, getServerSN, succClientSN, succServerSN )

type TlsM h g = ErrorT CS.Alert (StateT (CS.HandshakeState h g) (HandleMonad h))

evalTlsM :: HandleLike h => 
	TlsM h g a -> CS.HandshakeState h g -> HandleMonad h (Either CS.Alert a)
evalTlsM = evalStateT . runErrorT

data Partner = Server | Client deriving (Show, Eq)

getBuf, getWBuf ::  HandleLike h =>
	CS.ClientId -> TlsM h g (CS.ContentType, BS.ByteString)
getBuf = gets . CS.getBuf; getWBuf = gets . CS.getWBuf

setBuf, setWBuf :: HandleLike h =>
	CS.ClientId -> (CS.ContentType, BS.ByteString) -> TlsM h g ()
setBuf = (modify .) . CS.setBuf; setWBuf = (modify .) . CS.setWBuf

getServerSn, getClientSn :: HandleLike h => CS.ClientId -> TlsM h g Word64
getServerSn = gets . CS.getServerSN; getClientSn = gets . CS.getClientSN

succServerSn, succClientSn :: HandleLike h => CS.ClientId -> TlsM h g ()
succServerSn = modify . CS.succServerSN; succClientSn = modify . CS.succClientSN

withRandom :: HandleLike h => (gen -> (a, gen)) -> TlsM h gen a
withRandom p = do
	(x, g') <- p `liftM` gets CS.randomGen
	modify $ CS.setRandomGen g'
	return x

randomByteString :: (HandleLike h, CPRG g) => Int -> TlsM h g BS.ByteString
randomByteString = withRandom . cprgGenerate

thlGet :: HandleLike h => h -> Int -> TlsM h g BS.ByteString
thlGet = ((lift . lift) .) . hlGet

thlPut :: HandleLike h => h -> BS.ByteString -> TlsM h g ()
thlPut = ((lift . lift) .) . hlPut

thlClose :: HandleLike h => h -> TlsM h g ()
thlClose = lift . lift . hlClose

thlDebug :: HandleLike h =>
	h -> DebugLevel h -> BS.ByteString -> TlsM h gen ()
thlDebug = (((lift . lift) .) .) . hlDebug

thlError :: HandleLike h => h -> BS.ByteString -> TlsM h g a
thlError = ((lift . lift) .) . hlError
