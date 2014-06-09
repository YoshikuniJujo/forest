{-# LANGUAGE PackageImports, OverloadedStrings, TupleSections, TypeFamilies #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module ClientState (
--	TlsClientState(..),
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

import Data.Word
import qualified Data.ByteString as BS
import "crypto-random" Crypto.Random

{-

data TlsClientState gen = TlsClientState {
	tlsRandomGen :: gen,
	tlsClientStateList :: [TlsClientStateOne gen] }

data TlsClientStateOne gen {
	tlsBuffer :: BS.ByteString,
	tlsClientSequenceNumber :: Word64,
	tlsServerSequenceNumber :: Word 64 }

-}

data TlsClientState gen = TlsClientState {
	tlsBuffer :: BS.ByteString,
	tlsRandomGen :: gen,
	tlsClientSequenceNumber :: Word64,
	tlsServerSequenceNumber :: Word64 }

data ClientId = ClientId Int deriving Show

newClientId :: TlsClientState gen -> (ClientId, TlsClientState gen)
newClientId s = (ClientId 0, s)

setBuffer :: ClientId -> BS.ByteString -> TlsClientState gen -> TlsClientState gen
setBuffer cid bs st = st { tlsBuffer = bs }

getBuffer :: ClientId -> TlsClientState gen -> BS.ByteString
getBuffer cid = tlsBuffer

setRandomGen :: gen -> TlsClientState gen -> TlsClientState gen
setRandomGen rg st = st { tlsRandomGen = rg }

getRandomGenSt :: TlsClientState gen -> gen
getRandomGenSt = tlsRandomGen

setClientSequenceNumber, setServerSequenceNumber ::
	ClientId -> Word64 -> TlsClientState gen -> TlsClientState gen
setClientSequenceNumber cid sn st = st { tlsClientSequenceNumber = sn }
setServerSequenceNumber cid sn st = st { tlsServerSequenceNumber = sn }

getClientSequenceNumber, getServerSequenceNumber ::
	ClientId -> TlsClientState gen -> Word64
getClientSequenceNumber cid = tlsClientSequenceNumber
getServerSequenceNumber cid = tlsServerSequenceNumber

initialTlsState :: CPRG gen => gen -> TlsClientState gen
initialTlsState g = TlsClientState {
		tlsBuffer = "",
		tlsRandomGen = g,
		tlsClientSequenceNumber = 1,
		tlsServerSequenceNumber = 1 }
