module Extension (
	ExtensionList, parseExtensionList, extensionListToByteString,

	emptyBS, ByteStringM,
	Extension(..),
	EcPointFormat(..),
	NamedCurve(..),
) where

import Prelude hiding (head)

import Control.Applicative

import ByteStringMonad
-- import Basic
-- import ToByteString
import Parts

import qualified Data.ByteString as BS

type ExtensionList = [Extension]

parseExtensionList :: ByteStringM ExtensionList
parseExtensionList = section 2 $ list parseExtension

extensionListToByteString :: ExtensionList -> ByteString
extensionListToByteString =
	lenBodyToByteString 2 . BS.concat . map extensionToByteString

data Extension
	= ExtensionServerName [ServerName]
	| ExtensionEllipticCurve [NamedCurve]
	| ExtensionEcPointFormat [EcPointFormat]
	| ExtensionSessionTicketTls ByteString
	| ExtensionNextProtocolNegotiation ByteString
	| ExtensionRenegotiationInfo ByteString
	| ExtensionRaw ExtensionType ByteString
	deriving Show

parseExtension :: ByteStringM Extension
parseExtension = do
	et <- parseExtensionType
	section 2 $ case et of
		ExtensionTypeServerName -> section 2 $
			ExtensionServerName <$> list1 parseServerName
		ExtensionTypeEllipticCurve -> section 2 $
			ExtensionEllipticCurve <$> list1 parseNamedCurve
		ExtensionTypeEcPointFormat -> section 1 $
			ExtensionEcPointFormat <$> list1 parseEcPointFormat
		ExtensionTypeSessionTicketTls ->
			ExtensionSessionTicketTls <$> whole
		ExtensionTypeNextProtocolNegotiation ->
			ExtensionNextProtocolNegotiation <$> whole
		ExtensionTypeRenegotiationInfo ->
			ExtensionRenegotiationInfo <$> takeLen 1
		_ -> ExtensionRaw et <$> whole


extensionToByteString :: Extension -> ByteString
extensionToByteString (ExtensionServerName sns) = extensionToByteString .
	ExtensionRaw ExtensionTypeServerName . lenBodyToByteString 2 .
		BS.concat $ map serverNameToByteString sns
extensionToByteString (ExtensionEllipticCurve ecs) = extensionToByteString .
	ExtensionRaw ExtensionTypeEllipticCurve . lenBodyToByteString 2 .
		BS.concat $ map namedCurveToByteString ecs
extensionToByteString (ExtensionEcPointFormat epf) = extensionToByteString .
	ExtensionRaw ExtensionTypeEcPointFormat . lenBodyToByteString 1 .
		BS.concat $ map ecPointFormatToByteString epf
extensionToByteString (ExtensionSessionTicketTls stt) = extensionToByteString $
	ExtensionRaw ExtensionTypeSessionTicketTls stt
extensionToByteString (ExtensionNextProtocolNegotiation npn) = extensionToByteString $
	ExtensionRaw ExtensionTypeNextProtocolNegotiation npn
extensionToByteString (ExtensionRenegotiationInfo ri) = extensionToByteString .
	ExtensionRaw ExtensionTypeRenegotiationInfo $ lenBodyToByteString 1 ri
extensionToByteString (ExtensionRaw et body) = extensionTypeToByteString et `append`
	lenBodyToByteString 2 body

data ExtensionType
	= ExtensionTypeServerName
	| ExtensionTypeEllipticCurve
	| ExtensionTypeEcPointFormat
	| ExtensionTypeSessionTicketTls
	| ExtensionTypeNextProtocolNegotiation
	| ExtensionTypeRenegotiationInfo
	| ExtensionTypeRaw Word16
	deriving Show

parseExtensionType :: ByteStringM ExtensionType
parseExtensionType = do
	et <- takeWord16
	return $ case et of
		0 -> ExtensionTypeServerName
		10 -> ExtensionTypeEllipticCurve
		11 -> ExtensionTypeEcPointFormat
		35 -> ExtensionTypeSessionTicketTls
		13172 -> ExtensionTypeNextProtocolNegotiation
		65281 -> ExtensionTypeRenegotiationInfo
		_ -> ExtensionTypeRaw et

extensionTypeToByteString :: ExtensionType -> ByteString
extensionTypeToByteString ExtensionTypeServerName = word16ToByteString 0
extensionTypeToByteString ExtensionTypeEllipticCurve = word16ToByteString 10
extensionTypeToByteString ExtensionTypeEcPointFormat = word16ToByteString 11
extensionTypeToByteString ExtensionTypeSessionTicketTls = word16ToByteString 35
extensionTypeToByteString ExtensionTypeNextProtocolNegotiation = word16ToByteString 13172
extensionTypeToByteString ExtensionTypeRenegotiationInfo = word16ToByteString 65281
extensionTypeToByteString (ExtensionTypeRaw et) = word16ToByteString et

data ServerName
	= ServerNameHostName ByteString
	| ServerNameRaw NameType ByteString
	deriving Show

parseServerName :: ByteStringM ServerName
parseServerName = do
	nt <- parseNameType
	section 2 $ case nt of
		NameTypeHostName -> ServerNameHostName <$> whole
		_ -> ServerNameRaw nt <$> whole

serverNameToByteString :: ServerName -> ByteString
serverNameToByteString (ServerNameHostName nm) = serverNameToByteString $
	ServerNameRaw NameTypeHostName nm
serverNameToByteString (ServerNameRaw nt nm) =
	nameTypeToByteString nt `append` lenBodyToByteString 2 nm

data NameType
	= NameTypeHostName
	| NameTypeRaw Word8
	deriving Show

parseNameType :: ByteStringM NameType
parseNameType = do
	nt <- headBS "3"
	return $ case nt of
		0 -> NameTypeHostName
		_ -> NameTypeRaw nt

nameTypeToByteString :: NameType -> ByteString
nameTypeToByteString NameTypeHostName = pack [0]
nameTypeToByteString (NameTypeRaw nt) = pack [nt]

data EcPointFormat
	= EcPointFormatUncompressed
	| EcPointFormatRaw Word8
	deriving Show

parseEcPointFormat :: ByteStringM EcPointFormat
parseEcPointFormat = do
	epf <- headBS "4"
	return $ case epf of
		0 -> EcPointFormatUncompressed
		_ -> EcPointFormatRaw epf

ecPointFormatToByteString :: EcPointFormat -> ByteString
ecPointFormatToByteString EcPointFormatUncompressed = pack [0]
ecPointFormatToByteString (EcPointFormatRaw epf) = pack [epf]
