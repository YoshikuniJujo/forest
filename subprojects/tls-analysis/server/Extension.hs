module Extension (
	parseExtensionList',
	Bytable(..),

	takeLen',

	ExtensionList, parseExtensionList, extensionListToByteString,

	BS.concat, emptyBS, ByteStringM, takeBS, section',

	Parsable'(..), Parsable(..),
	lenBodyToByteString, headBS, Random(..), Version(..), CipherSuite(..),
	CipherSuiteKeyEx(..), CipherSuiteMsgEnc(..),
	SignatureAlgorithm(..), HashAlgorithm(..), ContentType(..),
	evalByteStringM,
) where

import Prelude hiding (head, concat)

import Control.Applicative
import Control.Monad

import qualified Data.ByteString as BS

import Data.Bits
import Data.Word
import NewTypes

import qualified Codec.Bytable as B
import Codec.Bytable.BigEndian

type ExtensionList = [Extension]

parseExtensionList :: Monad m => (Int -> m BS.ByteString) -> m ExtensionList
parseExtensionList rd = section' rd 2 . list $ parseExtension takeBS

parseExtensionList' :: B.BytableM [Extension]
parseExtensionList' = do
	len <- B.take 2
	B.list len B.parse

extensionListToByteString :: ExtensionList -> BS.ByteString
extensionListToByteString =
	lenBodyToByteString 2 .  BS.concat . map extensionToByteString

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
	parse = parseExtension'

parseExtension' :: B.BytableM Extension
parseExtension' = do
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

parseExtension :: Monad m => (Int -> m BS.ByteString) -> m Extension
parseExtension rd = do
	et <- (either error id . B.fromByteString) `liftM` rd 2
	len0 <- byteStringToInt `liftM` rd 2
	case et of
		ExtensionTypeServerName -> do
			len <- byteStringToInt `liftM` rd 2
			bs <- rd len
			return . ExtensionServerName . either error id $
				B.evalBytableM (B.list len B.parse) bs
		ExtensionTypeEllipticCurve -> do
			len <- byteStringToInt `liftM` rd 2
			bs <- rd len
			return . ExtensionEllipticCurve . either error id $
				B.evalBytableM (B.list len $ B.take 2) bs
		ExtensionTypeEcPointFormat -> do
			len <- byteStringToInt `liftM` rd 1
			bs <- rd len
			return . ExtensionEcPointFormat . either error id $
				B.evalBytableM (B.list len $ B.take 1) bs
		ExtensionTypeSessionTicketTls -> do
			bs <- rd len0
			return $ ExtensionSessionTicketTls bs
		ExtensionTypeNextProtocolNegotiation -> do
			bs <- rd len0
			return $ ExtensionNextProtocolNegotiation bs
		ExtensionTypeRenegotiationInfo -> do
			len <- byteStringToInt `liftM` rd 1
			bs <- rd len
			return $ ExtensionRenegotiationInfo bs
		_ -> do	bs <- rd len0
			return $ ExtensionRaw et bs

extensionToByteString :: Extension -> BS.ByteString
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
extensionToByteString (ExtensionRaw et body) = extensionTypeToByteString et `BS.append`
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

parseExtensionType :: Monad m => (Int -> m BS.ByteString) -> m ExtensionType
parseExtensionType rd = (either error id . byteStringToExtensionType) `liftM` rd 2

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
extensionTypeToByteString ExtensionTypeServerName = word16ToByteString 0
extensionTypeToByteString ExtensionTypeEllipticCurve = word16ToByteString 10
extensionTypeToByteString ExtensionTypeEcPointFormat = word16ToByteString 11
extensionTypeToByteString ExtensionTypeSessionTicketTls = word16ToByteString 35
extensionTypeToByteString ExtensionTypeNextProtocolNegotiation = word16ToByteString 13172
extensionTypeToByteString ExtensionTypeRenegotiationInfo = word16ToByteString 65281
extensionTypeToByteString (ExtensionTypeRaw et) = word16ToByteString et

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
	nameTypeToByteString nt `BS.append` lenBodyToByteString 2 nm

data NameType
	= NameTypeHostName
	| NameTypeRaw Word8
	deriving Show

instance B.Bytable NameType where
	fromByteString = byteStringToNameType
	toByteString = nameTypeToByteString

parseNameType :: ByteStringM NameType
parseNameType = either error id . byteStringToNameType <$> takeBS 1

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

parseEcPointFormat :: ByteStringM EcPointFormat
parseEcPointFormat = either error id . byteStringToEcPointFormat <$> takeBS 1

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
