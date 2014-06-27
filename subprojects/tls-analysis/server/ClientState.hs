{-# LANGUAGE OverloadedStrings, TupleSections, PackageImports #-}

module ClientState (
	HandshakeState, initState, ClientId, newClientId, Keys(..), nullKeys,
	ContentType(..), Alert(..), AlertLevel(..), AlertDesc(..),
	CipherSuite(..), KeyExchange(..), BulkEncryption(..),
	randomGen, setRandomGen,
	getBuf, setBuf, getWBuf, setWBuf,
	getClientSN, getServerSN, succClientSN, succServerSN,
) where

import "monads-tf" Control.Monad.Error.Class (Error(strMsg))
import Data.Maybe (fromJust)
import Data.Word (Word8, Word64)
import Data.String (IsString(..))

import qualified Data.ByteString as BS
import qualified Codec.Bytable as B

import CipherSuite (CipherSuite(..), KeyExchange(..), BulkEncryption(..))

data HandshakeState h g = HandshakeState {
	randomGen :: g, nextClientId :: Int,
	clientStates :: [(ClientId, StateOne g)] }

initState :: g -> HandshakeState h g
initState g = HandshakeState{ randomGen = g, nextClientId = 0, clientStates = [] }

data ClientId = ClientId Int deriving (Show, Eq)

newClientId :: HandshakeState h g -> (ClientId, HandshakeState h g)
newClientId s = (ClientId i ,) s{
	nextClientId = succ i,
	clientStates = (ClientId i, so) : sos }
	where
	i = nextClientId s
	so = StateOne {
		rBuffer = (CTNull, ""), wBuffer = (CTNull, ""),
		clientSN = 0, serverSN = 0 }
	sos = clientStates s

data StateOne g = StateOne {
	rBuffer :: (ContentType, BS.ByteString),
	wBuffer :: (ContentType, BS.ByteString),
	clientSN :: Word64, serverSN :: Word64 }

getClientState :: ClientId -> HandshakeState h g -> StateOne g
getClientState i = fromJust' "getClientState" . lookup i . clientStates

setClientState :: ClientId -> StateOne g -> Modify (HandshakeState h g)
setClientState i so s = s { clientStates = (i, so) : clientStates s }

modifyClientState :: ClientId -> Modify (StateOne g) -> Modify (HandshakeState h g)
modifyClientState i f s = setClientState i (f $ getClientState i s) s

data Keys = Keys {
	kCachedCS :: CipherSuite,
	kReadCS :: CipherSuite, kWriteCS :: CipherSuite,
	kMasterSecret :: BS.ByteString,
	kReadMacKey :: BS.ByteString, kWriteMacKey :: BS.ByteString,
	kReadKey :: BS.ByteString, kWriteKey :: BS.ByteString }
	deriving (Show, Eq)

nullKeys :: Keys
nullKeys = Keys {
	kCachedCS = CipherSuite KE_NULL BE_NULL,
	kReadCS = CipherSuite KE_NULL BE_NULL,
	kWriteCS = CipherSuite KE_NULL BE_NULL,
	kMasterSecret = "",
	kReadMacKey = "", kWriteMacKey = "", kReadKey = "", kWriteKey = "" }

data ContentType
	= CTCCSpec | CTAlert | CTHandshake | CTAppData | CTNull | CTRaw Word8
	deriving (Show, Eq)

instance B.Bytable ContentType where
	encode CTNull = BS.pack [0]
	encode CTCCSpec = BS.pack [20]
	encode CTAlert = BS.pack [21]
	encode CTHandshake = BS.pack [22]
	encode CTAppData = BS.pack [23]
	encode (CTRaw ct) = BS.pack [ct]
	decode "\0" = Right CTNull
	decode "\20" = Right CTCCSpec
	decode "\21" = Right CTAlert
	decode "\22" = Right CTHandshake
	decode "\23" = Right CTAppData
	decode bs | [ct] <- BS.unpack bs = Right $ CTRaw ct
	decode _ = Left "ClientState.decodeCT"

data Alert = Alert AlertLevel AlertDesc String | NotDetected String
	deriving Show

data AlertLevel = ALWarning | ALFatal | ALRaw Word8 deriving Show

data AlertDesc
	= ADCloseNotify            | ADUnexpectedMessage  | ADBadRecordMac
	| ADUnsupportedCertificate | ADCertificateExpired | ADCertificateUnknown
	| ADIllegalParameter       | ADUnknownCa          | ADDecodeError
	| ADDecryptError           | ADProtocolVersion    | ADRaw Word8
	deriving Show

instance Error Alert where
	strMsg = NotDetected

instance IsString Alert where
	fromString = NotDetected

setRandomGen :: g -> HandshakeState h g -> HandshakeState h g
setRandomGen rg st = st { randomGen = rg }

getBuf :: ClientId -> HandshakeState h g -> (ContentType, BS.ByteString)
getBuf i = rBuffer . fromJust' "getBuf" . lookup i . clientStates

setBuf :: ClientId -> (ContentType, BS.ByteString) -> Modify (HandshakeState h g)
setBuf i = modifyClientState i . \bs st -> st { rBuffer = bs }

getWBuf :: ClientId -> HandshakeState h g -> (ContentType, BS.ByteString)
getWBuf i = wBuffer . fromJust' "getWriteBuffer" . lookup i . clientStates

setWBuf :: ClientId -> (ContentType, BS.ByteString) -> Modify (HandshakeState h g)
setWBuf i = modifyClientState i . \bs st -> st{ wBuffer = bs }

getClientSN, getServerSN :: ClientId -> HandshakeState h g -> Word64
getClientSN i = clientSN . fromJust . lookup i . clientStates
getServerSN i = serverSN . fromJust . lookup i . clientStates

succClientSN, succServerSN :: ClientId -> Modify (HandshakeState h g)
succClientSN i = modifyClientState i $ \s -> s{ clientSN = succ $ clientSN s }
succServerSN i = modifyClientState i $ \s -> s{ serverSN = succ $ serverSN s }

type Modify s = s -> s

fromJust' :: String -> Maybe a -> a
fromJust' _ (Just x) = x
fromJust' msg _ = error msg
