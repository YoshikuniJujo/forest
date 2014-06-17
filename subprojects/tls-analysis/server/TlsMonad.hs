{-# LANGUAGE OverloadedStrings, PackageImports, RankNTypes, TupleSections,
	FlexibleContexts #-}

module TlsMonad (
	TlsM, run,
	thlPut, thlGet, thlDebug, thlError, thlClose,
	getBuf, setBuf, withRandom,
	getServerSn, getClientSn, succServerSn, succClientSn,

	CS.ContentType(..),
	CS.CipherSuite(..), CS.KeyExchange(..), CS.BulkEncryption(..),
	CS.Keys(..),
	CS.TlsClientState, CS.ClientId,
	CS.initialTlsState,

	throwError, runErrorT, catchError, ErrorType, Error, MonadError, lift,
	modify, StateT(..),
	
	CS.Alert(..), CS.AlertLevel(..), CS.AlertDescription(..),
	CS.alertToByteString, strToAlert,

	CS.newClientId, CS.nullKeys,
) where

import Prelude hiding (read)

import "monads-tf" Control.Monad.State
import "monads-tf" Control.Monad.Error
import "monads-tf" Control.Monad.Error.Class
import Data.Word
import Data.HandleLike

import qualified Data.ByteString as BS

import qualified ClientState as CS

run :: HandleLike h => TlsM h g a -> g -> HandleMonad h a
run = (liftM fst .) . runClient

runClient :: HandleLike h =>
	TlsM h g a -> g -> HandleMonad h (a, CS.TlsClientState h g)
runClient s g = do
	(ret, st') <- s `runTlsM` CS.initialTlsState g
	case ret of
		Right r -> return (r, st')
		Left msg -> error $ show msg

type TlsM h g = ErrorT CS.Alert (StateT (HandshakeState h g) (HandleMonad h))

runTlsM :: HandleLike h =>
	TlsM h g a -> HandshakeState h g ->
	HandleMonad h (Either CS.Alert a, HandshakeState h g)
runTlsM m st = runErrorT m `runStateT` st

data Partner = Server | Client deriving (Show, Eq)

getBuf ::  HandleLike h =>
	CS.ClientId -> TlsM h g (Maybe CS.ContentType, BS.ByteString)
getBuf = gets . CS.getBuffer

setBuf :: HandleLike h =>
	CS.ClientId -> (Maybe CS.ContentType, BS.ByteString) -> TlsM h g ()
setBuf = (modify .) . CS.setBuffer

getServerSn, getClientSn :: HandleLike h => CS.ClientId -> TlsM h g Word64
getServerSn = gets . CS.getServerSequenceNumber
getClientSn = gets . CS.getClientSequenceNumber

succServerSn, succClientSn :: HandleLike h => CS.ClientId -> TlsM h g ()
succServerSn = modify . CS.succServerSequenceNumber
succClientSn = modify . CS.succClientSequenceNumber

withRandom :: HandleLike h => (gen -> (a, gen)) -> TlsM h gen a
withRandom p = do
	gen <- gets randomGen
	let (x, gen') = p gen
	modify $ setRandomGen gen'
	return x

thlDebug :: HandleLike h =>
	h -> DebugLevel h -> BS.ByteString -> TlsM h gen ()
thlDebug = (((lift . lift) .) .) . hlDebug

thlGet :: HandleLike h => h -> Int -> TlsM h g BS.ByteString
thlGet = ((lift . lift) .) . hlGet

thlPut :: HandleLike h => h -> BS.ByteString -> TlsM h g ()
thlPut = ((lift . lift) .) . hlPut

thlError :: HandleLike h => h -> BS.ByteString -> TlsM h g a
thlError = ((lift . lift) .) . hlError

thlClose :: HandleLike h => h -> TlsM h g ()
thlClose = lift . lift . hlClose

type HandshakeState h gen = CS.TlsClientState h gen

type Modify s = s -> s

randomGen :: HandshakeState h gen -> gen
randomGen = CS.getRandomGen

setRandomGen :: gen -> Modify (HandshakeState h gen)
setRandomGen = CS.setRandomGen

strToAlert :: String -> CS.Alert
strToAlert = strMsg
