{-# LANGUAGE PackageImports, OverloadedStrings, TupleSections, TypeFamilies #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module OcMonad (
	TlsClientM,
	thlPut, thlGet, thlError, thlClose,
	getBuf, setBuf, withRandomGen,
	getServerSn, getClientSn, succServerSn, succClientSn,

	ContentType(..), CipherSuite(..), KeyExchange, BulkEncryption(..),
	Keys(..),
	TlsClientState, ClientId,
	initialTlsState, clientIdZero, initialTlsStateWithClientZero,
) where

import Prelude hiding (read)

import Data.Word
import qualified Data.ByteString as BS
import System.IO
import "crypto-random" Crypto.Random

import Data.HandleLike

import ClientState

import "monads-tf" Control.Monad.State

type family HandleRandomGen h

type instance HandleRandomGen Handle = SystemRNG

type TlsClientM h g = StateT (TlsClientState h g) (HandleMonad h)

tGets :: HandleLike h => (TlsClientState h g -> a) -> TlsClientM h g a
tGets = gets

tModify :: HandleLike h =>
	(TlsClientState h g -> TlsClientState h g) -> TlsClientM h g ()
tModify = modify

thlError :: HandleLike h => h -> BS.ByteString -> TlsClientM h g a
thlError = (lift .) . hlError

thlPut :: HandleLike h => h -> BS.ByteString -> TlsClientM h g ()
thlPut = (lift .) . hlPut

thlGet :: HandleLike h => h -> Int -> TlsClientM h g BS.ByteString
thlGet = (lift .) . hlGet

thlClose :: HandleLike h => h -> TlsClientM h g ()
thlClose = lift . hlClose

withRandomGen :: HandleLike h => (gen -> (a, gen)) -> TlsClientM h gen a
withRandomGen r = do
	(x, gen) <- tGets $ r . getRandomGen
	tModify $ setRandomGen gen
	return x

getServerSn :: HandleLike h => ClientId -> TlsClientM h gen Word64
getServerSn = gets . getServerSequenceNumber

succServerSn :: HandleLike h => ClientId -> TlsClientM h gen ()
succServerSn = modify . succServerSequenceNumber

getClientSn :: HandleLike h => ClientId -> TlsClientM h gen Word64
getClientSn = gets . getClientSequenceNumber

succClientSn :: HandleLike h => ClientId -> TlsClientM h gen ()
succClientSn = modify . succClientSequenceNumber

getBuf :: HandleLike h =>
	ClientId -> TlsClientM h g (Maybe ContentType, BS.ByteString)
getBuf = gets . getBuffer

setBuf :: HandleLike h =>
	ClientId -> (Maybe ContentType, BS.ByteString) -> TlsClientM h g ()
setBuf = (modify .) . setBuffer
