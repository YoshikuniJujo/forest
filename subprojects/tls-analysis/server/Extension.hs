module Extension (
	ExtensionList,
	SignatureAlgorithm(..), HashAlgorithm(..), NamedCurve(..),
) where

import Prelude hiding (head, concat)

import Control.Applicative

import qualified Data.ByteString as BS

import Data.Bits
import Data.Word
-- import NamedCurve
import SignHashAlgorithm(SignatureAlgorithm(..), HashAlgorithm(..))

import qualified Codec.Bytable as B

type ExtensionList = [Extension]

data Extension
	= ExtensionServerName [ServerName]
	| ExtensionEllipticCurve [NamedCurve]
	| ExtensionEcPointFormat [EcPointFormat]
	| ExtensionSessionTicketTls BS.ByteString
	| ExtensionNextProtocolNegotiation BS.ByteString
	| ExtensionRenegotiationInfo BS.ByteString
	| ExtensionRaw ExtensionType BS.ByteString
	deriving Show

instance B.Bytable Extension where
	fromByteString = B.evalBytableM B.parse
	toByteString = extensionToByteString

instance B.Parsable Extension where
	parse = parseExtension

parseExtension :: B.BytableM Extension
parseExtension = do
	et <- B.take 2
	len0 <- B.take 2
	case et of
		ExtensionTypeServerName -> do
			len <- B.take 2
			ExtensionServerName <$> B.list len B.parse
		ExtensionTypeEllipticCurve -> do
			len <- B.take 2
			ExtensionEllipticCurve <$> B.list len (B.take 2)
		ExtensionTypeEcPointFormat -> do
			len <- B.take 1
			ExtensionEcPointFormat <$> B.list len (B.take 1)
		ExtensionTypeSessionTicketTls ->
			ExtensionSessionTicketTls <$> B.take len0
		ExtensionTypeNextProtocolNegotiation ->
			ExtensionNextProtocolNegotiation <$> B.take len0
		ExtensionTypeRenegotiationInfo -> do
			len <- B.take 1
			ExtensionRenegotiationInfo <$> B.take len
		_ -> ExtensionRaw et <$> B.take len0

extensionToByteString :: Extension -> BS.ByteString
extensionToByteString (ExtensionServerName sns) = extensionToByteString .
	ExtensionRaw ExtensionTypeServerName . B.addLength (undefined :: Word16) .
		BS.concat $ map serverNameToByteString sns
extensionToByteString (ExtensionEllipticCurve ecs) = extensionToByteString .
	ExtensionRaw ExtensionTypeEllipticCurve . B.addLength (undefined :: Word16) .
		BS.concat $ map B.toByteString ecs
extensionToByteString (ExtensionEcPointFormat epf) = extensionToByteString .
	ExtensionRaw ExtensionTypeEcPointFormat . B.addLength (undefined :: Word8) .
		BS.concat $ map ecPointFormatToByteString epf
extensionToByteString (ExtensionSessionTicketTls stt) = extensionToByteString $
	ExtensionRaw ExtensionTypeSessionTicketTls stt
extensionToByteString (ExtensionNextProtocolNegotiation npn) = extensionToByteString $
	ExtensionRaw ExtensionTypeNextProtocolNegotiation npn
extensionToByteString (ExtensionRenegotiationInfo ri) = extensionToByteString .
	ExtensionRaw ExtensionTypeRenegotiationInfo $ B.addLength (undefined :: Word8) ri
extensionToByteString (ExtensionRaw et body) = extensionTypeToByteString et `BS.append`
	B.addLength (undefined :: Word16) body

data ExtensionType
	= ExtensionTypeServerName
	| ExtensionTypeEllipticCurve
	| ExtensionTypeEcPointFormat
	| ExtensionTypeSessionTicketTls
	| ExtensionTypeNextProtocolNegotiation
	| ExtensionTypeRenegotiationInfo
	| ExtensionTypeRaw Word16
	deriving Show

instance B.Bytable ExtensionType where
	fromByteString = byteStringToExtensionType
	toByteString = extensionTypeToByteString

byteStringToExtensionType :: BS.ByteString -> Either String ExtensionType
byteStringToExtensionType bs = case BS.unpack bs of
	[w1, w2] -> Right $ case fromIntegral w1 `shiftL` 8 .|. fromIntegral w2 of
		0 -> ExtensionTypeServerName
		10 -> ExtensionTypeEllipticCurve
		11 -> ExtensionTypeEcPointFormat
		35 -> ExtensionTypeSessionTicketTls
		13172 -> ExtensionTypeNextProtocolNegotiation
		65281 -> ExtensionTypeRenegotiationInfo
		et -> ExtensionTypeRaw et
	_ -> Left "Extension.byteStringToExtensionType"

extensionTypeToByteString :: ExtensionType -> BS.ByteString
extensionTypeToByteString ExtensionTypeServerName = B.toByteString (0 :: Word16)
extensionTypeToByteString ExtensionTypeEllipticCurve = B.toByteString (10 :: Word16)
extensionTypeToByteString ExtensionTypeEcPointFormat = B.toByteString (11 :: Word16)
extensionTypeToByteString ExtensionTypeSessionTicketTls = B.toByteString (35 :: Word16)
extensionTypeToByteString ExtensionTypeNextProtocolNegotiation = B.toByteString (13172 :: Word16)
extensionTypeToByteString ExtensionTypeRenegotiationInfo = B.toByteString (65281 :: Word16)
extensionTypeToByteString (ExtensionTypeRaw et) = B.toByteString et

data ServerName
	= ServerNameHostName BS.ByteString
	| ServerNameRaw NameType BS.ByteString
	deriving Show

instance B.Parsable ServerName where
	parse = parseServerName

instance B.Bytable ServerName where
	fromByteString = B.evalBytableM parseServerName
	toByteString = serverNameToByteString

parseServerName :: B.BytableM ServerName
parseServerName = do
	nt <- B.take 1
	len <- B.take 2
	nm <- B.take len
	return $ case nt of
		NameTypeHostName -> ServerNameHostName nm
		_ -> ServerNameRaw nt nm

serverNameToByteString :: ServerName -> BS.ByteString
serverNameToByteString (ServerNameHostName nm) = serverNameToByteString $
	ServerNameRaw NameTypeHostName nm
serverNameToByteString (ServerNameRaw nt nm) =
	nameTypeToByteString nt `BS.append` B.addLength (undefined :: Word16) nm

data NameType
	= NameTypeHostName
	| NameTypeRaw Word8
	deriving Show

instance B.Bytable NameType where
	fromByteString = byteStringToNameType
	toByteString = nameTypeToByteString

byteStringToNameType :: BS.ByteString -> Either String NameType
byteStringToNameType bs = case BS.unpack bs of
	[nt] -> Right $ case nt of
		0 -> NameTypeHostName
		_ -> NameTypeRaw nt
	_ -> Left "Extension.byteStringToNameType"

nameTypeToByteString :: NameType -> BS.ByteString
nameTypeToByteString NameTypeHostName = BS.pack [0]
nameTypeToByteString (NameTypeRaw nt) = BS.pack [nt]

data EcPointFormat
	= EcPointFormatUncompressed
	| EcPointFormatRaw Word8
	deriving Show

instance B.Bytable EcPointFormat where
	fromByteString = byteStringToEcPointFormat
	toByteString = ecPointFormatToByteString

byteStringToEcPointFormat :: BS.ByteString -> Either String EcPointFormat
byteStringToEcPointFormat bs = case BS.unpack bs of
	[epf] -> Right $ case epf of
		0 -> EcPointFormatUncompressed
		_ -> EcPointFormatRaw epf
	_ -> Left "Extension.byteStringToEcPointFormat"

ecPointFormatToByteString :: EcPointFormat -> BS.ByteString
ecPointFormatToByteString EcPointFormatUncompressed = BS.pack [0]
ecPointFormatToByteString (EcPointFormatRaw epf) = BS.pack [epf]

data NamedCurve
	= Secp256r1
	| Secp384r1
	| Secp521r1
	| NamedCurveRaw Word16
	deriving Show

instance B.Bytable NamedCurve where
	fromByteString = byteStringToNamedCurve
	toByteString = namedCurveToByteString

byteStringToNamedCurve :: BS.ByteString -> Either String NamedCurve
byteStringToNamedCurve bs = case BS.unpack bs of
	[w1, w2] -> Right $ case fromIntegral w1 `shiftL` 8 .|. fromIntegral w2 of
		23 -> Secp256r1
		24 -> Secp384r1
		25 -> Secp521r1
		nc -> NamedCurveRaw nc
	_ -> Left "Types.byteStringToNamedCurve"

namedCurveToByteString :: NamedCurve -> BS.ByteString
namedCurveToByteString (Secp256r1) = B.toByteString (23 :: Word16)
namedCurveToByteString (Secp384r1) = B.toByteString (24 :: Word16)
namedCurveToByteString (Secp521r1) = B.toByteString (25 :: Word16)
namedCurveToByteString (NamedCurveRaw nc) = B.toByteString nc
