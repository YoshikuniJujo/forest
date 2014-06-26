{-# LANGUAGE OverloadedStrings, TupleSections, TypeFamilies, PackageImports #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module ClientState (
	HandshakeState,
	ClientId,
	newClientId,
	getBuffer, setBuffer,
	getWriteBuffer, setWriteBuffer,
	setRandomGen, randomGen,
	getClientSN, getServerSN, succClientSN, succServerSN,
	initialTlsState,

	ContentType(..),

	Keys(..),
	nullKeys,
	CipherSuite(..), KeyExchange(..), BulkEncryption(..),

	Alert(..), AlertLevel(..), AlertDescription(..),
	alertToByteString,
	alertLevelToWord8,
	alertDescriptionToWord8,
) where

import Prelude hiding (read)

import Data.Maybe
import Data.Word
import qualified Data.ByteString as BS

import qualified Codec.Bytable as B
import CipherSuite

import "monads-tf" Control.Monad.Error.Class
import Data.String

data HandshakeState h gen = TlsClientState {
	tlsRandomGen :: gen,
	tlsNextClientId :: Int,
	tlsClientStateList :: [(ClientId, TlsClientStateOne gen)] }

setClientState :: ClientId -> TlsClientStateOne gen ->
	HandshakeState h gen -> HandshakeState h gen
setClientState cid cso cs = cs {
	tlsClientStateList = (cid, cso) : tlsClientStateList cs }

fromJust' :: String -> Maybe a -> a
fromJust' _ (Just x) = x
fromJust' msg _ = error msg

getClientState :: ClientId -> HandshakeState h gen -> TlsClientStateOne gen
getClientState cid = fromJust' "getClientState" . lookup cid . tlsClientStateList

modifyClientState :: ClientId -> (TlsClientStateOne gen -> TlsClientStateOne gen) ->
	HandshakeState h gen -> HandshakeState h gen
modifyClientState cid f cs = let
	cso = getClientState cid cs in
	setClientState cid (f cso) cs

data TlsClientStateOne gen = TlsClientStateOne {
	tlsBuffer :: (ContentType, BS.ByteString),
	tlsWriteBuffer :: (ContentType, BS.ByteString),
	tlsClientSequenceNumber :: Word64,
	tlsServerSequenceNumber :: Word64 }

data ClientId = ClientId Int deriving (Show, Eq)

newClientId :: HandshakeState h gen -> (ClientId, HandshakeState h gen)
newClientId s = (ClientId cid ,) s {
	tlsNextClientId = succ cid,
	tlsClientStateList = (ClientId cid, cs) : sl }
	where
	cid = tlsNextClientId s
	cs = TlsClientStateOne {
		tlsBuffer = (CTNull, ""),
		tlsWriteBuffer = (CTNull, ""),
		tlsClientSequenceNumber = 0,
		tlsServerSequenceNumber = 0 }
	sl = tlsClientStateList s

getBuffer :: ClientId -> HandshakeState h gen -> (ContentType, BS.ByteString)
getBuffer cid = tlsBuffer . fromJust' "getBuffer" . lookup cid . tlsClientStateList

setBuffer ::
	ClientId -> (ContentType, BS.ByteString) -> Modify (HandshakeState h gen)
setBuffer cid = modifyClientState cid . sb
	where sb bs st = st { tlsBuffer = bs }

getWriteBuffer :: ClientId -> HandshakeState h gen -> (ContentType, BS.ByteString)
getWriteBuffer cid = tlsWriteBuffer .
	fromJust' "getWriteBuffer" . lookup cid . tlsClientStateList

setWriteBuffer ::
	ClientId -> (ContentType, BS.ByteString) -> Modify (HandshakeState h gen)
setWriteBuffer cid = modifyClientState cid . swb
	where swb bs st = st { tlsWriteBuffer = bs }

setRandomGen :: gen -> HandshakeState h gen -> HandshakeState h gen
setRandomGen rg st = st { tlsRandomGen = rg }

randomGen :: HandshakeState h gen -> gen
randomGen = tlsRandomGen

type Modify s = s -> s

succClientSN, succServerSN ::
	ClientId -> Modify (HandshakeState h gen)
succClientSN cid = modifyClientState cid scsn
	where scsn st@TlsClientStateOne { tlsClientSequenceNumber = s } =
		st { tlsClientSequenceNumber = succ s }
succServerSN cid = modifyClientState cid scsn
	where scsn st@TlsClientStateOne { tlsServerSequenceNumber = s } =
		st { tlsServerSequenceNumber = succ s }

getClientSN, getServerSN ::
	ClientId -> HandshakeState h gen -> Word64
getClientSN cid =
	tlsClientSequenceNumber . fromJust . lookup cid . tlsClientStateList
getServerSN cid =
	tlsServerSequenceNumber . fromJust . lookup cid . tlsClientStateList

initialTlsState :: gen -> HandshakeState h gen
initialTlsState g = TlsClientState {
	tlsRandomGen = g,
	tlsNextClientId = 0,
	tlsClientStateList = [] }

data ContentType
	= CTCCSpec
	| CTAlert
	| CTHandshake
	| CTAppData
	| CTNull
	| CTRaw Word8
	deriving (Show, Eq)

instance B.Bytable ContentType where
	decode = Right . byteStringToContentType
	encode = contentTypeToByteString

byteStringToContentType :: BS.ByteString -> ContentType
byteStringToContentType "" = error "Types.byteStringToContentType: empty"
byteStringToContentType "\20" = CTCCSpec
byteStringToContentType "\21" = CTAlert
byteStringToContentType "\22" = CTHandshake
byteStringToContentType "\23" = CTAppData
byteStringToContentType bs = let [ct] = BS.unpack bs in CTRaw ct

contentTypeToByteString :: ContentType -> BS.ByteString
contentTypeToByteString CTCCSpec = BS.pack [20]
contentTypeToByteString CTAlert = BS.pack [21]
contentTypeToByteString CTHandshake = BS.pack [22]
contentTypeToByteString CTAppData = BS.pack [23]
contentTypeToByteString CTNull = BS.pack [0]
contentTypeToByteString (CTRaw ct) = BS.pack [ct]

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
alertToByteString (NotDetected m) = error $ "alertToByteString: " ++ m

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
