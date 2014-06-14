{-# LANGUAGE PackageImports, OverloadedStrings, TupleSections, TypeFamilies #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module ClientState (
	TlsClientState,
	ClientId,
	newClientId,
	setBuffer, getBuffer,
	setRandomGen, getRandomGenSt,
	setClientSequenceNumber, getClientSequenceNumber,
	setServerSequenceNumber, getServerSequenceNumber,
	initialTlsState,
) where

import Prelude hiding (read)

import Data.Maybe
import Data.Word
import qualified Data.ByteString as BS
import "crypto-random" Crypto.Random

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
	tlsBuffer :: BS.ByteString,
	tlsClientSequenceNumber :: Word64,
	tlsServerSequenceNumber :: Word64 }

{-

data TlsClientState gen = TlsClientState {
	tlsBuffer :: BS.ByteString,
	tlsRandomGen :: gen,
	tlsClientSequenceNumber :: Word64,
	tlsServerSequenceNumber :: Word64 }

-}

data ClientId = ClientId Int deriving (Show, Eq)

newClientId :: TlsClientState gen -> (ClientId, TlsClientState gen)
newClientId s = (ClientId cid ,) s {
	tlsNextClientId = succ cid,
	tlsClientStateList = (ClientId cid, cs) : sl }
	where
	cid = tlsNextClientId s
	cs = TlsClientStateOne {
		tlsBuffer = "",
		tlsClientSequenceNumber = 1,
		tlsServerSequenceNumber = 1 }
	sl = tlsClientStateList s

setBuffer :: ClientId -> BS.ByteString -> TlsClientState gen -> TlsClientState gen
setBuffer cid = modifyClientState cid . sb
	where sb bs st = st { tlsBuffer = bs }

getBuffer :: ClientId -> TlsClientState gen -> BS.ByteString
getBuffer cid = tlsBuffer . fromJust . lookup cid . tlsClientStateList

setRandomGen :: gen -> TlsClientState gen -> TlsClientState gen
setRandomGen rg st = st { tlsRandomGen = rg }

getRandomGenSt :: TlsClientState gen -> gen
getRandomGenSt = tlsRandomGen

setClientSequenceNumber, setServerSequenceNumber ::
	ClientId -> Word64 -> TlsClientState gen -> TlsClientState gen
setClientSequenceNumber cid = modifyClientState cid . scsn
	where scsn s st = st { tlsClientSequenceNumber = s }
setServerSequenceNumber cid = modifyClientState cid . sssn
	where sssn s st = st { tlsServerSequenceNumber = s }

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
