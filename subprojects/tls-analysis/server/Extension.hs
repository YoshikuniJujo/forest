{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Extension (
	ExtensionList,
	SignatureAlgorithm(..), HashAlgorithm(..), -- NamedCurve(..),
) where

import Prelude hiding (head, concat)

import Control.Applicative

import qualified Data.ByteString as BS
import qualified Crypto.Types.PubKey.DH as DH
import qualified Crypto.Types.PubKey.ECC as ECC

import Data.Bits
import Data.Word
import SignHashAlgorithm(SignatureAlgorithm(..), HashAlgorithm(..))

import qualified Codec.Bytable as B

type ExtensionList = [Extension]

data Extension
	= ExtensionServerName [ServerName]
	| ExtensionEllipticCurve [ECC.CurveName]
	| ExtensionEcPointFormat [EcPointFormat]
	| ExtensionSessionTicketTls BS.ByteString
	| ExtensionNextProtocolNegotiation BS.ByteString
	| ExtensionRenegotiationInfo BS.ByteString
	| ExtensionRaw ExtensionType BS.ByteString
	deriving Show

instance B.Bytable Extension where
	decode = B.evalBytableM B.parse
	encode = extensionToByteString

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
	ExtensionRaw ExtensionTypeServerName . B.addLen (undefined :: Word16) .
		BS.concat $ map serverNameToByteString sns
extensionToByteString (ExtensionEllipticCurve ecs) = extensionToByteString .
	ExtensionRaw ExtensionTypeEllipticCurve . B.addLen (undefined :: Word16) .
		BS.concat $ map B.encode ecs
extensionToByteString (ExtensionEcPointFormat epf) = extensionToByteString .
	ExtensionRaw ExtensionTypeEcPointFormat . B.addLen (undefined :: Word8) .
		BS.concat $ map ecPointFormatToByteString epf
extensionToByteString (ExtensionSessionTicketTls stt) = extensionToByteString $
	ExtensionRaw ExtensionTypeSessionTicketTls stt
extensionToByteString (ExtensionNextProtocolNegotiation npn) = extensionToByteString $
	ExtensionRaw ExtensionTypeNextProtocolNegotiation npn
extensionToByteString (ExtensionRenegotiationInfo ri) = extensionToByteString .
	ExtensionRaw ExtensionTypeRenegotiationInfo $ B.addLen (undefined :: Word8) ri
extensionToByteString (ExtensionRaw et body) = extensionTypeToByteString et `BS.append`
	B.addLen (undefined :: Word16) body

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
	decode = byteStringToExtensionType
	encode = extensionTypeToByteString

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
extensionTypeToByteString ExtensionTypeServerName = B.encode (0 :: Word16)
extensionTypeToByteString ExtensionTypeEllipticCurve = B.encode (10 :: Word16)
extensionTypeToByteString ExtensionTypeEcPointFormat = B.encode (11 :: Word16)
extensionTypeToByteString ExtensionTypeSessionTicketTls = B.encode (35 :: Word16)
extensionTypeToByteString ExtensionTypeNextProtocolNegotiation = B.encode (13172 :: Word16)
extensionTypeToByteString ExtensionTypeRenegotiationInfo = B.encode (65281 :: Word16)
extensionTypeToByteString (ExtensionTypeRaw et) = B.encode et

data ServerName
	= ServerNameHostName BS.ByteString
	| ServerNameRaw NameType BS.ByteString
	deriving Show

instance B.Parsable ServerName where
	parse = parseServerName

instance B.Bytable ServerName where
	decode = B.evalBytableM parseServerName
	encode = serverNameToByteString

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
	nameTypeToByteString nt `BS.append` B.addLen (undefined :: Word16) nm

data NameType
	= NameTypeHostName
	| NameTypeRaw Word8
	deriving Show

instance B.Bytable NameType where
	decode = byteStringToNameType
	encode = nameTypeToByteString

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
	decode = byteStringToEcPointFormat
	encode = ecPointFormatToByteString

byteStringToEcPointFormat :: BS.ByteString -> Either String EcPointFormat
byteStringToEcPointFormat bs = case BS.unpack bs of
	[epf] -> Right $ case epf of
		0 -> EcPointFormatUncompressed
		_ -> EcPointFormatRaw epf
	_ -> Left "Extension.byteStringToEcPointFormat"

ecPointFormatToByteString :: EcPointFormat -> BS.ByteString
ecPointFormatToByteString EcPointFormatUncompressed = BS.pack [0]
ecPointFormatToByteString (EcPointFormatRaw epf) = BS.pack [epf]

{-
data NamedCurve
	= Secp256r1
	| Secp384r1
	| Secp521r1
	| NamedCurveRaw Word16
	deriving Show

instance B.Bytable NamedCurve where
	decode = byteStringToNamedCurve
	encode = namedCurveToByteString

byteStringToNamedCurve :: BS.ByteString -> Either String NamedCurve
byteStringToNamedCurve bs = case BS.unpack bs of
	[w1, w2] -> Right $ case fromIntegral w1 `shiftL` 8 .|. fromIntegral w2 of
		23 -> Secp256r1
		24 -> Secp384r1
		25 -> Secp521r1
		nc -> NamedCurveRaw nc
	_ -> Left "Types.byteStringToNamedCurve"

namedCurveToByteString :: NamedCurve -> BS.ByteString
namedCurveToByteString (Secp256r1) = B.encode (23 :: Word16)
namedCurveToByteString (Secp384r1) = B.encode (24 :: Word16)
namedCurveToByteString (Secp521r1) = B.encode (25 :: Word16)
namedCurveToByteString (NamedCurveRaw nc) = B.encode nc
-}

instance B.Bytable ECC.CurveName where
	decode = byteStringToCurveName
	encode = curveNameToByteString

byteStringToCurveName :: BS.ByteString -> Either String ECC.CurveName
byteStringToCurveName bs = case BS.unpack bs of
	[w1, w2] -> case fromIntegral w1 `shiftL` 8 .|. fromIntegral w2 of
		(23 :: Word16) -> Right ECC.SEC_p256r1
		24 -> Right ECC.SEC_p384r1
		25 -> Right ECC.SEC_p521r1
		_ -> Left "Extension.byteStringToCurveName: unknown curve"
	_ -> Left "Extension.byteStringToCurveName: bad format"

curveNameToByteString :: ECC.CurveName -> BS.ByteString
curveNameToByteString ECC.SEC_p256r1 = B.encode (23 :: Word16)
curveNameToByteString ECC.SEC_p384r1 = B.encode (24 :: Word16)
curveNameToByteString ECC.SEC_p521r1 = B.encode (25 :: Word16)
curveNameToByteString _ = error "Extension.curveNameToByteString: not implemented"

instance B.Bytable DH.Params where
	decode = B.evalBytableM $ DH.Params <$> B.take 2 <*> B.take 2
	encode (DH.Params dhP dhG) = BS.concat [
		B.addLen (undefined :: Word16) $ B.encode dhP,
		B.addLen (undefined :: Word16) $ B.encode dhG ]

instance B.Bytable DH.PublicNumber where
	decode = B.evalBytableM $ fromInteger <$> (B.take =<< B.take 2)
	encode = B.addLen (undefined :: Word16) .
		B.encode . \(DH.PublicNumber pn) -> pn

instance B.Bytable ECC.Point where
	decode bs = case BS.uncons $ BS.tail bs of
		Just (4, rest) -> Right $ let (x, y) = BS.splitAt 32 rest in
			ECC.Point	(either error id $ B.decode x)
					(either error id $ B.decode y)
		_ -> Left "KeyAgreement.hs: ECC.Point.decode"
	encode (ECC.Point x y) = B.addLen (undefined :: Word8) .
		BS.cons 4 $ BS.append (B.encode x) (B.encode y)
	encode ECC.PointO = error "KeyAgreement.hs: EC.Point.encode"

data EcCurveType = ExplicitPrime | ExplicitChar2 | NamedCurve | EcCurveTypeRaw Word8
	deriving Show

instance B.Bytable EcCurveType where
	decode = undefined
	encode ExplicitPrime = BS.pack [1]
	encode ExplicitChar2 = BS.pack [2]
	encode NamedCurve = BS.pack [3]
	encode (EcCurveTypeRaw w) = BS.pack [w]

instance B.Bytable ECC.Curve where
	decode = undefined
	encode = encodeCurve

encodeCurve :: ECC.Curve -> BS.ByteString
encodeCurve c
	| c == ECC.getCurveByName ECC.SEC_p256r1 =
		B.encode NamedCurve `BS.append` B.encode ECC.SEC_p256r1
	| otherwise = error "TlsServer.encodeCurve: not implemented"
