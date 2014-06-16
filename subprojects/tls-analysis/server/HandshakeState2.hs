module HandshakeState2 (
	HandshakeState,
	initHandshakeState,
	byteStringBuffer, setByteStringBuffer,
	randomGen, setRandomGen,
	updateHandshakeHash, getHandshakeHash,
	clientSequenceNumber, succClientSequenceNumber,
	serverSequenceNumber, succServerSequenceNumber,

	CS.ContentType,
	CS.Keys(..),
	CS.nullKeys,
	CS.CipherSuite(..), CS.KeyExchange, CS.BulkEncryption(..),
) where

import Data.Word
import qualified Data.ByteString as BS

import qualified ClientState as CS

type HandshakeState h gen = CS.TlsClientState h gen

type Modify s = s -> s

initHandshakeState :: gen -> HandshakeState h gen
initHandshakeState = 
	(\(i, s) -> if i == CS.clientIdZero
		then s
		else error "HandshakeState.initHandshakeState")
	. CS.newClientId' . CS.initialTlsState

byteStringBuffer :: HandshakeState h gen -> (Maybe CS.ContentType, BS.ByteString)
byteStringBuffer = CS.getBuffer CS.clientIdZero

setByteStringBuffer ::
	(Maybe CS.ContentType, BS.ByteString) -> Modify (HandshakeState h gen)
setByteStringBuffer = CS.setBuffer CS.clientIdZero

updateHandshakeHash :: BS.ByteString -> Modify (HandshakeState h gen)
updateHandshakeHash = CS.updateHandshakeHash CS.clientIdZero

getHandshakeHash :: HandshakeState h gen -> BS.ByteString
getHandshakeHash = CS.getHandshakeHash CS.clientIdZero

clientSequenceNumber :: HandshakeState h gen -> Word64
clientSequenceNumber = CS.getClientSequenceNumber CS.clientIdZero

succClientSequenceNumber :: Modify (HandshakeState h gen)
succClientSequenceNumber = CS.succClientSequenceNumber CS.clientIdZero

serverSequenceNumber :: HandshakeState h gen -> Word64
serverSequenceNumber = CS.getServerSequenceNumber CS.clientIdZero

succServerSequenceNumber :: Modify (HandshakeState h gen)
succServerSequenceNumber = CS.succServerSequenceNumber CS.clientIdZero

randomGen :: HandshakeState h gen -> gen
randomGen = CS.getRandomGen

setRandomGen :: gen -> Modify (HandshakeState h gen)
setRandomGen = CS.setRandomGen
