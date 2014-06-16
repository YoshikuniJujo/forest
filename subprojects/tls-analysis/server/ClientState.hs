{-# LANGUAGE PackageImports, OverloadedStrings, TupleSections, TypeFamilies #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module ClientState (
	clientIdZero,
	TlsClientState,
	ClientId,
	newClientId,
	setBuffer, getBuffer,
	setRandomGen, getRandomGen,
	updateHandshakeHash, getHandshakeHash,
	succClientSequenceNumber, getClientSequenceNumber,
	succServerSequenceNumber, getServerSequenceNumber,
	initialTlsState,
) where

import Prelude hiding (read)

import Data.Maybe
import Data.Word
import qualified Data.ByteString as BS
import "crypto-random" Crypto.Random

import qualified Crypto.Hash.SHA256 as SHA256

import ContentType

data TlsClientState gen = TlsClientState {
	tlsRandomGen :: gen,
	tlsNextClientId :: Int,
	tlsClientStateList :: [(ClientId, TlsClientStateOne gen)] }

setClientState :: ClientId -> TlsClientStateOne gen ->
	TlsClientState gen -> TlsClientState gen
setClientState cid cso cs = cs {
	tlsClientStateList = (cid, cso) : tlsClientStateList cs }

getClientState :: ClientId -> TlsClientState gen -> TlsClientStateOne gen
getClientState cid = fromJust . lookup cid . tlsClientStateList

modifyClientState :: ClientId -> (TlsClientStateOne gen -> TlsClientStateOne gen) ->
	TlsClientState gen -> TlsClientState gen
modifyClientState cid f cs = let
	cso = getClientState cid cs in
	setClientState cid (f cso) cs

data TlsClientStateOne gen = TlsClientStateOne {
	tlsBuffer :: (Maybe ContentType, BS.ByteString),
	tlsClientSequenceNumber :: Word64,
	tlsServerSequenceNumber :: Word64,
	tlsHandshakeHashCtx :: SHA256.Ctx
	}

data ClientId = ClientId Int deriving (Show, Eq)

clientIdZero :: ClientId
clientIdZero = ClientId 0

newClientId :: TlsClientState gen -> (ClientId, TlsClientState gen)
newClientId s = (ClientId cid ,) s {
	tlsNextClientId = succ cid,
	tlsClientStateList = (ClientId cid, cs) : sl }
	where
	cid = tlsNextClientId s
	cs = TlsClientStateOne {
		tlsBuffer = (Nothing, ""),
		tlsClientSequenceNumber = 1,
		tlsServerSequenceNumber = 1,
		tlsHandshakeHashCtx = SHA256.init
		}
	sl = tlsClientStateList s

setBuffer :: ClientId ->
	(Maybe ContentType, BS.ByteString) -> Modify (TlsClientState gen)
setBuffer cid = modifyClientState cid . sb
	where sb bs st = st { tlsBuffer = bs }

getBuffer :: ClientId -> TlsClientState gen -> (Maybe ContentType, BS.ByteString)
getBuffer cid = tlsBuffer . fromJust . lookup cid . tlsClientStateList

setRandomGen :: gen -> TlsClientState gen -> TlsClientState gen
setRandomGen rg st = st { tlsRandomGen = rg }

getRandomGen :: TlsClientState gen -> gen
getRandomGen = tlsRandomGen

updateHandshakeHash :: ClientId -> BS.ByteString -> Modify (TlsClientState gen)
updateHandshakeHash cid = modifyClientState cid . uh
	where uh bs st@TlsClientStateOne { tlsHandshakeHashCtx = ctx } =
		st { tlsHandshakeHashCtx = SHA256.update ctx bs }

getHandshakeHash :: ClientId -> TlsClientState gen -> BS.ByteString
getHandshakeHash cid = SHA256.finalize .
	tlsHandshakeHashCtx . fromJust . lookup cid . tlsClientStateList

type Modify s = s -> s

succClientSequenceNumber, succServerSequenceNumber ::
	ClientId -> Modify (TlsClientState gen)
succClientSequenceNumber cid = modifyClientState cid scsn
	where scsn st@TlsClientStateOne { tlsClientSequenceNumber = s } =
		st { tlsClientSequenceNumber = succ s }
succServerSequenceNumber cid = modifyClientState cid scsn
	where scsn st@TlsClientStateOne { tlsServerSequenceNumber = s } =
		st { tlsServerSequenceNumber = succ s }

getClientSequenceNumber, getServerSequenceNumber ::
	ClientId -> TlsClientState gen -> Word64
getClientSequenceNumber cid =
	tlsClientSequenceNumber . fromJust . lookup cid . tlsClientStateList
getServerSequenceNumber cid =
	tlsServerSequenceNumber . fromJust . lookup cid . tlsClientStateList

initialTlsState :: CPRG gen => gen -> TlsClientState gen
initialTlsState g = TlsClientState {
	tlsRandomGen = g,
	tlsNextClientId = 0,
	tlsClientStateList = [] }
