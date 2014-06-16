{-# LANGUAGE OverloadedStrings, RankNTypes, TupleSections, FlexibleContexts #-}

module HandshakeState (
	HandshakeState,
	initHandshakeState,
	byteStringBuffer, setByteStringBuffer,
	randomGen, setRandomGen,
	updateHandshakeHash, getHandshakeHash,
	clientSequenceNumber, succClientSequenceNumber,
	serverSequenceNumber, succServerSequenceNumber,
) where

import Prelude hiding (read)

import Data.Word

import qualified Data.ByteString as BS
import qualified Crypto.Hash.SHA256 as SHA256

import ContentType

data HandshakeState h gen = HandshakeState {
	tlssByteStringBuffer :: (Maybe ContentType, BS.ByteString),

	tlssRandomGen :: gen,
	tlssClientSequenceNumber :: Word64,
	tlssServerSequenceNumber :: Word64,

	tlssSha256Ctx :: SHA256.Ctx
	}

initHandshakeState :: gen -> HandshakeState h gen
initHandshakeState gen = HandshakeState {
	tlssByteStringBuffer = (Nothing, ""),
	tlssRandomGen = gen,
	tlssSha256Ctx = SHA256.init,
	tlssClientSequenceNumber = 0,
	tlssServerSequenceNumber = 0 }

type Modify s = s -> s

randomGen :: HandshakeState h gen -> gen
randomGen = tlssRandomGen

setRandomGen :: gen -> Modify (HandshakeState h gen)
setRandomGen gen tlss = tlss { tlssRandomGen = gen }

byteStringBuffer :: HandshakeState h gen -> (Maybe ContentType, BS.ByteString)
byteStringBuffer = tlssByteStringBuffer

setByteStringBuffer ::
	(Maybe ContentType, BS.ByteString) -> Modify (HandshakeState h gen)
setByteStringBuffer b tlss = tlss { tlssByteStringBuffer = b }

-- data Partner = Server | Client deriving (Show, Eq)

updateHandshakeHash :: BS.ByteString -> Modify (HandshakeState h gen)
updateHandshakeHash bs tlss@HandshakeState{ tlssSha256Ctx = sha256 } =
	tlss { tlssSha256Ctx = SHA256.update sha256 bs }

getHandshakeHash :: HandshakeState h gen -> BS.ByteString
getHandshakeHash HandshakeState { tlssSha256Ctx = ctx } = SHA256.finalize ctx

clientSequenceNumber :: HandshakeState h gen -> Word64
clientSequenceNumber = tlssClientSequenceNumber

succClientSequenceNumber :: Modify (HandshakeState h gen)
succClientSequenceNumber hs@HandshakeState { tlssClientSequenceNumber = sn } =
	hs { tlssClientSequenceNumber = succ sn }

serverSequenceNumber :: HandshakeState h gen -> Word64
serverSequenceNumber = tlssServerSequenceNumber

succServerSequenceNumber :: Modify (HandshakeState h gen)
succServerSequenceNumber hs@HandshakeState { tlssServerSequenceNumber = sn } =
	hs { tlssServerSequenceNumber = succ sn }
