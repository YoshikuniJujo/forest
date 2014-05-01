{-# LANGUAGE OverloadedStrings, TupleSections #-}

module Extension (
	Extension, extension, extensionToByteString
) where

import Control.Applicative
import Control.Arrow

import Data.Word
import qualified Data.ByteString as BS

import Parts
import Tools

data Extension
	= ExtensionServerName [ServerName]
	| ExtensionEllipticCurve [NamedCurve]
	| ExtensionEcPointFormat [EcPointFormat]
	| ExtensionRenegotiationInfo RenegotiationInfo
	| ExtensionRaw ExtensionType BS.ByteString
	deriving Show

extensionSelect :: ExtensionType -> BS.ByteString -> Either String Extension
extensionSelect ExtensionTypeServerName bs = ExtensionServerName . fst <$>
	list 2 serverName bs
extensionSelect ExtensionTypeEllipticCurve bs =
	ExtensionEllipticCurve . fst <$> list 2 namedCurve bs
extensionSelect ExtensionTypeEcPointFormat bs =
	ExtensionEcPointFormat . fst <$> list 1 ecPointFormat bs
extensionSelect ExtensionTypeRenegotiationInfo bs =
	ExtensionRenegotiationInfo . fst <$> renegotiationInfo bs
extensionSelect et bs = return $ ExtensionRaw et bs

extensionToByteString :: Extension -> BS.ByteString
extensionToByteString (ExtensionServerName sns) =
	extensionTypeToByteString ExtensionTypeServerName `BS.append`
	bodyToBS 2 (listToByteString 2 serverNameToByteString sns)
extensionToByteString (ExtensionEllipticCurve ec) =
	extensionTypeToByteString ExtensionTypeEllipticCurve `BS.append`
	bodyToBS 2 (listToByteString 2 namedCurveToByteString ec)
extensionToByteString (ExtensionEcPointFormat ecpf) =
	extensionTypeToByteString ExtensionTypeEcPointFormat `BS.append`
	bodyToBS 2 (listToByteString 1 ecPointFormatToByteString ecpf)
extensionToByteString (ExtensionRenegotiationInfo ri) =
	extensionTypeToByteString ExtensionTypeRenegotiationInfo `BS.append`
	bodyToBS 2 (renegotiationInfoToByteString ri)
extensionToByteString (ExtensionRaw et bs) =
	extensionTypeToByteString et `BS.append` bodyToBS 2 bs

data ExtensionType
	= ExtensionTypeServerName
	| ExtensionTypeEllipticCurve
	| ExtensionTypeEcPointFormat
	| ExtensionTypeSessionTicketTls
	| ExtensionTypeNextProtocolNegotiation
	| ExtensionTypeRenegotiationInfo
	| ExtensionTypeRaw Word16
	deriving Show

extensionTypeToByteString :: ExtensionType -> BS.ByteString
extensionTypeToByteString ExtensionTypeServerName = "\x00\x00"
extensionTypeToByteString ExtensionTypeEllipticCurve = "\x00\x0a"
extensionTypeToByteString ExtensionTypeEcPointFormat = "\x00\x0b"
extensionTypeToByteString ExtensionTypeSessionTicketTls = "\x00\x23"
extensionTypeToByteString ExtensionTypeNextProtocolNegotiation = "\x33\x74"
extensionTypeToByteString ExtensionTypeRenegotiationInfo = "\xff\x01"
extensionTypeToByteString (ExtensionTypeRaw w) = BS.pack $ word16ToWords w

extensionTypeSelect :: Word16 -> ExtensionType
extensionTypeSelect 0 = ExtensionTypeServerName
extensionTypeSelect 10 = ExtensionTypeEllipticCurve
extensionTypeSelect 11 = ExtensionTypeEcPointFormat
extensionTypeSelect 35 = ExtensionTypeSessionTicketTls
extensionTypeSelect 13172 = ExtensionTypeNextProtocolNegotiation
extensionTypeSelect 65281 = ExtensionTypeRenegotiationInfo
extensionTypeSelect w = ExtensionTypeRaw w

extension :: BS.ByteString -> Either String (Extension, BS.ByteString)
extension src = do
	(et, r1) <- first (extensionTypeSelect . wordsToWord16 . BS.unpack) <$>
		eitherSplitAt "extension" 2 src
	(len, r2) <- bsToLen 2 r1
	(body, r3) <- eitherSplitAt "extension" len r2
	(, r3) <$> extensionSelect et body

data ServerName
	= ServerName NameType BS.ByteString
	deriving Show

serverNameSelect :: NameType -> BS.ByteString -> ServerName
serverNameSelect nt bs = ServerName nt bs

serverNameToByteString :: ServerName -> BS.ByteString
serverNameToByteString (ServerName nt bs) =
	nameTypeToByteString nt `BS.append`
	lenToBS 2 bs `BS.append`
	bs

data NameType
	= NameTypeRaw Word8
	deriving Show

nameTypeSelect :: Word8 -> NameType
nameTypeSelect w = NameTypeRaw w

nameTypeToByteString :: NameType -> BS.ByteString
nameTypeToByteString (NameTypeRaw w) = BS.pack [w]

serverName :: BS.ByteString -> Either String (ServerName, BS.ByteString)
serverName src = do
	(nt, src') <- eitherUncons src
	(body, rest) <- getBody 2 src'
	return (serverNameSelect (nameTypeSelect nt) body, rest)

data RenegotiationInfo = RenegotiationInfo BS.ByteString
	deriving Show

renegotiationInfoToByteString :: RenegotiationInfo -> BS.ByteString
renegotiationInfoToByteString (RenegotiationInfo bs) = bodyToBS 1 bs

renegotiationInfo :: BS.ByteString -> Either String (RenegotiationInfo, BS.ByteString)
renegotiationInfo src = do
	(body, rest) <- getBody 1 src
	return (RenegotiationInfo body, rest)

data NamedCurve
	= Secp256r1
	| Secp384r1
	| Secp521r1
	| NamedCurveRaw Word16
	deriving Show

namedCurveSelect :: Word16 -> NamedCurve
namedCurveSelect 23 = Secp256r1
namedCurveSelect 24 = Secp384r1
namedCurveSelect 25 = Secp521r1
namedCurveSelect w = NamedCurveRaw w

namedCurveToByteString :: NamedCurve -> BS.ByteString
namedCurveToByteString Secp256r1 = "\x00\x17"
namedCurveToByteString Secp384r1 = "\x00\x18"
namedCurveToByteString Secp521r1 = "\x00\x19"
namedCurveToByteString (NamedCurveRaw w) = BS.pack $ word16ToWords w

namedCurve :: BS.ByteString -> Either String (NamedCurve, BS.ByteString)
namedCurve src = do
	(nc, rest) <- eitherSplitAt "namedCurve" 2 src
	return (namedCurveSelect $ wordsToWord16 $ BS.unpack nc, rest)

data EcPointFormat
	= EcPointFormatUncompressed
	| EcPointFormatRaw Word8
	deriving Show

ecPointFormatSelect :: Word8 -> EcPointFormat
ecPointFormatSelect 0 = EcPointFormatUncompressed
ecPointFormatSelect w = EcPointFormatRaw w

ecPointFormatToByteString :: EcPointFormat -> BS.ByteString
ecPointFormatToByteString EcPointFormatUncompressed = "\x00"
ecPointFormatToByteString (EcPointFormatRaw w) = BS.pack [w]

ecPointFormat :: BS.ByteString -> Either String (EcPointFormat, BS.ByteString)
ecPointFormat src = do
	(w, rest) <- eitherUncons src
	return (ecPointFormatSelect w, rest)

{-
data SessionTicket
	= SessionTicket BS.ByteString
	deriving Show

sessionTicketToByteString :: SessionTicket -> BS.ByteString
sessionTicketToByteString (SessionTicket bs) = bodyToBS 2 bs

sessionTicket :: BS.ByteString -> Either String (SessionTicket,
-}
