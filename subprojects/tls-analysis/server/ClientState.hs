{-# LANGUAGE OverloadedStrings, TupleSections, TypeFamilies, PackageImports #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module ClientState (
	TlsClientState,
	ClientId,
	newClientId,
	setBuffer, getBuffer,
	setRandomGen, getRandomGen,
	updateHandshakeHash, getHandshakeHash,
	succClientSequenceNumber, getClientSequenceNumber,
	succServerSequenceNumber, getServerSequenceNumber,
	initialTlsState,

	ContentType(..),

	Keys(..),
	nullKeys,
	CipherSuite(..), KeyExchange(..), BulkEncryption(..),

	Alert(..), AlertLevel(..), AlertDescription(..),
	alertToByteString,
) where

import Prelude hiding (read)

import Data.Maybe
import Data.Word
import qualified Data.ByteString as BS

import qualified Crypto.Hash.SHA256 as SHA256

import qualified Codec.Bytable as B
import CipherSuite

import "monads-tf" Control.Monad.Error.Class
import Data.String

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

newClientId :: TlsClientState h gen -> (ClientId, TlsClientState h gen)
newClientId s = (ClientId cid ,) s {
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

nullKeys :: Keys
nullKeys = Keys {
	kCachedCipherSuite = CipherSuite KE_NULL BE_NULL,
	kClientCipherSuite = CipherSuite KE_NULL BE_NULL,
	kServerCipherSuite = CipherSuite KE_NULL BE_NULL,

	kMasterSecret = "",
	kClientWriteMacKey = "",
	kServerWriteMacKey = "",
	kClientWriteKey = "",
	kServerWriteKey = "" }

data Keys = Keys {
	kCachedCipherSuite :: CipherSuite,
	kClientCipherSuite :: CipherSuite,
	kServerCipherSuite :: CipherSuite,

	kMasterSecret :: BS.ByteString,
	kClientWriteMacKey :: BS.ByteString,
	kServerWriteMacKey :: BS.ByteString,
	kClientWriteKey :: BS.ByteString,
	kServerWriteKey :: BS.ByteString }
	deriving (Show, Eq)

data Alert
	= Alert AlertLevel AlertDescription String
	| NotDetected String
	deriving Show

alertToByteString :: Alert -> BS.ByteString
alertToByteString (Alert al ad _) = "\21\3\3\0\2" `BS.append`
	BS.pack [alertLevelToWord8 al, alertDescriptionToWord8 ad]
alertToByteString alt = error $ "alertToByteString: " ++ show alt

data AlertLevel
	= AlertLevelWarning
	| AlertLevelFatal
	| AlertLevelRaw Word8
	deriving Show

alertLevelToWord8 :: AlertLevel -> Word8
alertLevelToWord8 AlertLevelWarning = 1
alertLevelToWord8 AlertLevelFatal = 2
alertLevelToWord8 (AlertLevelRaw al) = al

data AlertDescription
	= AlertDescriptionCloseNotify
	| AlertDescriptionUnexpectedMessage
	| AlertDescriptionBadRecordMac
	| AlertDescriptionUnsupportedCertificate
	| AlertDescriptionCertificateExpired
	| AlertDescriptionCertificateUnknown
	| AlertDescriptionIllegalParameter
	| AlertDescriptionUnknownCa
	| AlertDescriptionDecodeError
	| AlertDescriptionDecryptError
	| AlertDescriptionProtocolVersion
	| AlertDescriptionRaw Word8
	deriving Show

alertDescriptionToWord8 :: AlertDescription -> Word8
alertDescriptionToWord8 AlertDescriptionCloseNotify = 0
alertDescriptionToWord8 AlertDescriptionUnexpectedMessage = 10
alertDescriptionToWord8 AlertDescriptionBadRecordMac = 20
alertDescriptionToWord8 AlertDescriptionUnsupportedCertificate = 43
alertDescriptionToWord8 AlertDescriptionCertificateExpired = 45
alertDescriptionToWord8 AlertDescriptionCertificateUnknown = 46
alertDescriptionToWord8 AlertDescriptionIllegalParameter = 47
alertDescriptionToWord8 AlertDescriptionUnknownCa = 48
alertDescriptionToWord8 AlertDescriptionDecodeError = 50
alertDescriptionToWord8 AlertDescriptionDecryptError = 51
alertDescriptionToWord8 AlertDescriptionProtocolVersion = 70
alertDescriptionToWord8 (AlertDescriptionRaw ad) = ad

instance Error Alert where
	strMsg = NotDetected

instance IsString Alert where
	fromString = NotDetected
