module Parts (
) where

import ByteStringMonad

data ProtocolVersion = ProtocolVersion Word8 Word8 deriving Show

parseProtocolVersion

protocolVersionToByteString :: ProtocolVersion -> ByteString
protocolVersionToByteString (ProtocolVersion vmjr vmnr) = pack [vmjr, vmnr]

data Random = Random ByteString deriving Show
