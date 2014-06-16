{-# LANGUAGE OverloadedStrings, TupleSections, TypeFamilies #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module ClientState (
	clientIdZero,
	TlsClientState,
	ClientId,
	newClientId,
	newClientId',
	setBuffer, getBuffer,
	setRandomGen, getRandomGen,
	updateHandshakeHash, getHandshakeHash,
	succClientSequenceNumber, getClientSequenceNumber,
	succServerSequenceNumber, getServerSequenceNumber,
	initialTlsState,

	ContentType(..),
) where

import Prelude hiding (read)

import Data.Maybe
import Data.Word
import qualified Data.ByteString as BS

import qualified Crypto.Hash.SHA256 as SHA256

import qualified Codec.Bytable as B
-- import ContentType

data TlsClientState h gen = TlsClientState {
	tlsRandomGen :: gen,
	tlsNextClientId :: Int,
	tlsClientStateList :: [(ClientId, TlsClientStateOne gen)] }

setClientState :: ClientId -> TlsClientStateOne gen ->
	TlsClientState h gen -> TlsClientState h gen
setClientState cid cso cs = cs {
	tlsClientStateList = (cid, cso) : tlsClientStateList cs }

fromJust' :: String -> Maybe a -> a
fromJust' _ (Just x) = x
fromJust' msg _ = error msg

getClientState :: ClientId -> TlsClientState h gen -> TlsClientStateOne gen
getClientState cid = fromJust' "getClientState" . lookup cid . tlsClientStateList

modifyClientState :: ClientId -> (TlsClientStateOne gen -> TlsClientStateOne gen) ->
	TlsClientState h gen -> TlsClientState h gen
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

newClientId :: TlsClientState h gen -> (ClientId, TlsClientState h gen)
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

newClientId' :: TlsClientState h gen -> (ClientId, TlsClientState h gen)
newClientId' s = (ClientId cid ,) s {
	tlsNextClientId = succ cid,
	tlsClientStateList = (ClientId cid, cs) : sl }
	where
	cid = tlsNextClientId s
	cs = TlsClientStateOne {
		tlsBuffer = (Nothing, ""),
		tlsClientSequenceNumber = 0,
		tlsServerSequenceNumber = 0,
		tlsHandshakeHashCtx = SHA256.init
		}
	sl = tlsClientStateList s

setBuffer :: ClientId ->
	(Maybe ContentType, BS.ByteString) -> Modify (TlsClientState h gen)
setBuffer cid = modifyClientState cid . sb
	where sb bs st = st { tlsBuffer = bs }

getBuffer :: ClientId -> TlsClientState h gen -> (Maybe ContentType, BS.ByteString)
getBuffer cid = tlsBuffer . fromJust' "getBuffer" . lookup cid . tlsClientStateList

setRandomGen :: gen -> TlsClientState h gen -> TlsClientState h gen
setRandomGen rg st = st { tlsRandomGen = rg }

getRandomGen :: TlsClientState h gen -> gen
getRandomGen = tlsRandomGen

updateHandshakeHash :: ClientId -> BS.ByteString -> Modify (TlsClientState h gen)
updateHandshakeHash cid = modifyClientState cid . uh
	where uh bs st@TlsClientStateOne { tlsHandshakeHashCtx = ctx } =
		st { tlsHandshakeHashCtx = SHA256.update ctx bs }

getHandshakeHash :: ClientId -> TlsClientState h gen -> BS.ByteString
getHandshakeHash cid = SHA256.finalize .
	tlsHandshakeHashCtx . fromJust . lookup cid . tlsClientStateList

type Modify s = s -> s

succClientSequenceNumber, succServerSequenceNumber ::
	ClientId -> Modify (TlsClientState h gen)
succClientSequenceNumber cid = modifyClientState cid scsn
	where scsn st@TlsClientStateOne { tlsClientSequenceNumber = s } =
		st { tlsClientSequenceNumber = succ s }
succServerSequenceNumber cid = modifyClientState cid scsn
	where scsn st@TlsClientStateOne { tlsServerSequenceNumber = s } =
		st { tlsServerSequenceNumber = succ s }

getClientSequenceNumber, getServerSequenceNumber ::
	ClientId -> TlsClientState h gen -> Word64
getClientSequenceNumber cid =
	tlsClientSequenceNumber . fromJust . lookup cid . tlsClientStateList
getServerSequenceNumber cid =
	tlsServerSequenceNumber . fromJust . lookup cid . tlsClientStateList

initialTlsState :: gen -> TlsClientState h gen
initialTlsState g = TlsClientState {
	tlsRandomGen = g,
	tlsNextClientId = 0,
	tlsClientStateList = [] }

data ContentType
	= ContentTypeChangeCipherSpec
	| ContentTypeAlert
	| ContentTypeHandshake
	| ContentTypeApplicationData
	| ContentTypeRaw Word8
	deriving (Show, Eq)

instance B.Bytable ContentType where
	fromByteString = Right . byteStringToContentType
	toByteString = contentTypeToByteString

byteStringToContentType :: BS.ByteString -> ContentType
byteStringToContentType "" = error "Types.byteStringToContentType: empty"
byteStringToContentType "\20" = ContentTypeChangeCipherSpec
byteStringToContentType "\21" = ContentTypeAlert
byteStringToContentType "\22" = ContentTypeHandshake
byteStringToContentType "\23" = ContentTypeApplicationData
byteStringToContentType bs = let [ct] = BS.unpack bs in ContentTypeRaw ct

contentTypeToByteString :: ContentType -> BS.ByteString
contentTypeToByteString ContentTypeChangeCipherSpec = BS.pack [20]
contentTypeToByteString ContentTypeAlert = BS.pack [21]
contentTypeToByteString ContentTypeHandshake = BS.pack [22]
contentTypeToByteString ContentTypeApplicationData = BS.pack [23]
contentTypeToByteString (ContentTypeRaw ct) = BS.pack [ct]
