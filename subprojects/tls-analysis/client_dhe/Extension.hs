module Extension (
	ExtensionList, parseExtensionList, extensionListToByteString,

	concat, emptyBS, ByteStringM,
) where

import Prelude hiding (head, concat)

import Control.Applicative

import ByteStringMonad
-- import Basic
-- import ToByteString

type ExtensionList = [Extension]

parseExtensionList :: ByteStringM ExtensionList
parseExtensionList = section 2 $ list parseExtension

extensionListToByteString :: ExtensionList -> ByteString
extensionListToByteString =
	lenBodyToByteString 2 .  concat . map extensionToByteString

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
		concat $ map serverNameToByteString sns
extensionToByteString (ExtensionEllipticCurve ecs) = extensionToByteString .
	ExtensionRaw ExtensionTypeEllipticCurve . lenBodyToByteString 2 .
		concat $ map namedCurveToByteString ecs
extensionToByteString (ExtensionEcPointFormat epf) = extensionToByteString .
	ExtensionRaw ExtensionTypeEcPointFormat . lenBodyToByteString 1 .
		concat $ map ecPointFormatToByteString epf
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
	nt <- headBS
	return $ case nt of
		0 -> NameTypeHostName
		_ -> NameTypeRaw nt

nameTypeToByteString :: NameType -> ByteString
nameTypeToByteString NameTypeHostName = pack [0]
nameTypeToByteString (NameTypeRaw nt) = pack [nt]

data NamedCurve
	= Secp256r1
	| Secp384r1
	| Secp521r1
	| NamedCurveRaw Word16
	deriving Show

parseNamedCurve :: ByteStringM NamedCurve
parseNamedCurve = do
	nc <- takeWord16
	return $ case nc of
		23 -> Secp256r1
		24 -> Secp384r1
		25 -> Secp521r1
		_ -> NamedCurveRaw nc

namedCurveToByteString :: NamedCurve -> ByteString
namedCurveToByteString (Secp256r1) = word16ToByteString 23
namedCurveToByteString (Secp384r1) = word16ToByteString 24
namedCurveToByteString (Secp521r1) = word16ToByteString 25
namedCurveToByteString (NamedCurveRaw nc) = word16ToByteString nc

data EcPointFormat
	= EcPointFormatUncompressed
	| EcPointFormatRaw Word8
	deriving Show

parseEcPointFormat :: ByteStringM EcPointFormat
parseEcPointFormat = do
	epf <- headBS
	return $ case epf of
		0 -> EcPointFormatUncompressed
		_ -> EcPointFormatRaw epf

ecPointFormatToByteString :: EcPointFormat -> ByteString
ecPointFormatToByteString EcPointFormatUncompressed = pack [0]
ecPointFormatToByteString (EcPointFormatRaw epf) = pack [epf]
