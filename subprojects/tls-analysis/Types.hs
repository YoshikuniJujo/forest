module Types (
	ProtocolVersion(..), parseProtocolVersion, protocolVersionToByteString
) where

import Data.Word
import ByteStringMonad

data ProtocolVersion = ProtocolVersion Word8 Word8 deriving Show

parseProtocolVersion :: ByteStringM ProtocolVersion
parseProtocolVersion = do
	[vmjr, vmnr] <- takeWords 2
	return $ ProtocolVersion vmjr vmnr

protocolVersionToByteString :: ProtocolVersion -> ByteString
protocolVersionToByteString (ProtocolVersion vmjr vmnr) = pack [vmjr, vmnr]
