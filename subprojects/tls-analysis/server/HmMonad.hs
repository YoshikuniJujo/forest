{-# LANGUAGE OverloadedStrings, PackageImports, RankNTypes, TupleSections,
	FlexibleContexts #-}

module HmMonad (
	HandshakeM, handshakeM, runHandshakeM,
	thlPut, thlGet, thlDebug, thlError, thlClose,
	getBuf, setBuf, withRandom,
	getServerSn, getClientSn, succServerSn, succClientSn,

	CS.ContentType(..), CS.CipherSuite(..), CS.KeyExchange, CS.BulkEncryption(..),
	CS.Keys(..),
	CS.TlsClientState, CS.ClientId,
	CS.initialTlsState,
	
	getHash, updateH,

	throwError, runErrorT, catchError, ErrorType, Error, MonadError, lift,
	modify, StateT(..),
	
	CS.Alert(..), CS.AlertLevel(..), CS.AlertDescription(..),
	CS.alertToByteString, strToAlert,

	CS.newClientId, CS.nullKeys,

	eitherToError,
) where

import Prelude hiding (read)

import "monads-tf" Control.Monad.State
import "monads-tf" Control.Monad.Error
import "monads-tf" Control.Monad.Error.Class
import Data.Word
import Data.HandleLike

import qualified Data.ByteString as BS

import qualified ClientState as CS

type HandshakeM h gen =
	ErrorT CS.Alert (StateT (HandshakeState h gen) (HandleMonad h))

runHandshakeM :: HandleLike h =>
	HandshakeM h g a -> HandshakeState h g ->
	HandleMonad h (Either CS.Alert a, HandshakeState h g)
runHandshakeM m st = runErrorT m `runStateT` st

handshakeM :: HandleLike h => (HandshakeState h g ->
		HandleMonad h (Either CS.Alert a, HandshakeState h g)) ->
	HandshakeM h g a
handshakeM = ErrorT . StateT

data Partner = Server | Client deriving (Show, Eq)

updateH :: HandleLike h => CS.ClientId -> BS.ByteString -> HandshakeM h gen ()
updateH cid = modify . CS.updateHandshakeHash cid

getBuf ::  HandleLike h =>
	CS.ClientId -> HandshakeM h g (Maybe CS.ContentType, BS.ByteString)
getBuf = gets . CS.getBuffer

setBuf :: HandleLike h =>
	CS.ClientId -> (Maybe CS.ContentType, BS.ByteString) -> HandshakeM h g ()
setBuf = (modify .) . CS.setBuffer

getHash :: HandleLike h => CS.ClientId -> HandshakeM h g BS.ByteString
getHash = gets . CS.getHandshakeHash

getServerSn, getClientSn :: HandleLike h => CS.ClientId -> HandshakeM h g Word64
getServerSn = gets . CS.getServerSequenceNumber
getClientSn = gets . CS.getClientSequenceNumber

succServerSn, succClientSn :: HandleLike h => CS.ClientId -> HandshakeM h g ()
succServerSn = modify . CS.succServerSequenceNumber
succClientSn = modify . CS.succClientSequenceNumber

withRandom :: HandleLike h => (gen -> (a, gen)) -> HandshakeM h gen a
withRandom p = do
	gen <- gets randomGen
	let (x, gen') = p gen
	modify $ setRandomGen gen'
	return x

thlDebug :: HandleLike h =>
	h -> DebugLevel h -> BS.ByteString -> HandshakeM h gen ()
thlDebug = (((lift . lift) .) .) . hlDebug

thlGet :: HandleLike h => h -> Int -> HandshakeM h g BS.ByteString
thlGet = ((lift . lift) .) . hlGet

thlPut :: HandleLike h => h -> BS.ByteString -> HandshakeM h g ()
thlPut = ((lift . lift) .) . hlPut

thlError :: HandleLike h => h -> BS.ByteString -> HandshakeM h g a
thlError = ((lift . lift) .) . hlError

thlClose :: HandleLike h => h -> HandshakeM h g ()
thlClose = lift . lift . hlClose

type HandshakeState h gen = CS.TlsClientState h gen

type Modify s = s -> s

randomGen :: HandshakeState h gen -> gen
randomGen = CS.getRandomGen

setRandomGen :: gen -> Modify (HandshakeState h gen)
setRandomGen = CS.setRandomGen

strToAlert :: String -> CS.Alert
strToAlert = strMsg

eitherToError :: (Show msg, MonadError m, Error (ErrorType m)) => Either msg a -> m a
eitherToError = either (throwError . strMsg . show) return
