{-# LANGUAGE TupleSections, OverloadedStrings #-}

module ServerExtension (Extensions, extensions) where

import Prelude hiding (take)
import Control.Monad

import Data.Conduit
import qualified Data.Conduit.List as List
import Data.Conduit.Binary

import Data.Word
import Data.ByteString.Lazy (toStrict)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

import ServerName
import RenegotiationInfo
import EllipticCurve
import ECPointFormat
import Tools

extensions :: Monad m => Consumer BS.ByteString m (Maybe Extensions)
extensions = do
	mlen <- maybeLen 2
	case mlen of
		Just len -> do
			body <- take len
			return $ Just $ Extensions $ toStrict body
--			sourceLbs body $= parseExtensions $$ await
		_ -> return Nothing

parseExtensions :: Monad m => Conduit BS.ByteString m [Extension]
parseExtensions = yield =<< parseExtension =$ List.consume

parseExtension :: Monad m => Conduit BS.ByteString m Extension
parseExtension = do
	t <- take 2
	when (LBS.length t == 2) $ do
		eachExtension $ extensionType $ toWord16 t
		parseExtension

eachExtension :: Monad m => ExtensionType -> Conduit BS.ByteString m Extension
eachExtension ExtensionTypeServerName = do
	_mlen <- maybeLen 2
	serverNameList =$= List.map ExtensionServerName
eachExtension ExtensionTypeRenegotiationInfo = do
	_mlen <- maybeLen 2
	renegotiationInfo =$= List.map ExtensionRenegotiationInfo
eachExtension ExtensionTypeEllipticCurves = do
	_mlen <- maybeLen 2
	ellipticCurveList =$= List.map ExtensionEllipticCurve
eachExtension ExtensionTypeEcPointFormats = do
	_mlen <- maybeLen 2
	ecPointFormatList =$= List.map ExtensionECPointFormat
eachExtension ExtensionTypeSessionTicketTLS = do
	l <- getLen 2
	body <- take l
	yield $ ExtensionSessionTicketTLS $ toStrict body
eachExtension ExtensionTypeNextProtocolNegotiation = do
	0 <- getLen 2
	yield ExtensionNextProtocolNegotiation
eachExtension et = do
	mlen <- maybeLen 2
	case mlen of
		Just len -> do
			body <- take len
			yield $ ExtensionOthers et $ toStrict body
		_ -> return ()

toWord16 :: LBS.ByteString -> Word16
toWord16 bs = let
	w1 = LBS.head bs
	w2 = LBS.head $ LBS.tail bs in
	fromIntegral w1 * 256 + fromIntegral w2

-- type Extensions = [Extension]
data Extensions = Extensions BS.ByteString
	deriving Show

data Extension
	= ExtensionServerName ServerNameList
	| ExtensionRenegotiationInfo RenegotiationInfo
	| ExtensionEllipticCurve EllipticCurveList
	| ExtensionECPointFormat ECPointFormatList
	| ExtensionSessionTicketTLS BS.ByteString
	| ExtensionNextProtocolNegotiation
	| ExtensionOthers ExtensionType BS.ByteString
	deriving Show

data ExtensionType
	= ExtensionTypeServerName
	| ExtensionTypeEllipticCurves
	| ExtensionTypeEcPointFormats
	| ExtensionTypeSessionTicketTLS
	| ExtensionTypeNextProtocolNegotiation
	| ExtensionTypeRenegotiationInfo
	| ExtensionTypeOthers Word16
	deriving Show

extensionType :: Word16 -> ExtensionType
extensionType 0 = ExtensionTypeServerName
extensionType 10 = ExtensionTypeEllipticCurves
extensionType 11 = ExtensionTypeEcPointFormats
extensionType 35 = ExtensionTypeSessionTicketTLS
extensionType 13172 = ExtensionTypeNextProtocolNegotiation
extensionType 65281 = ExtensionTypeRenegotiationInfo
extensionType w = ExtensionTypeOthers w

{-
extensionsToByteString :: Extensions -> BS.ByteString
extensionsToByteString exts =
	lenToBS 2 (BS.length bs)
	`BS.append` bs
	where
	bs = BS.concat $ map extensionToByteString exts
extensionToByteString :: Extension -> BS.ByteString
extensionToByteString (ExtensionServerName sn) = "\x00\x00" `BS.append`
	lenToBS 2 (BS.length bs) `BS.append` bs
	where
	bs = serverNameListToByteString sn
extensionToByteString (ExtensionEllipticCurve ecs) = "\x00\x0a" `BS.append`
	lenToBS 2 (BS.length bs) `BS.append` bs
	where
	bs = ellipticCurveListToByteString ecs
extensionToByteString (ExtensionRenegotiationInfo r) = "\xff\x01" `BS.append`
	lenToBS 2 (BS.length bs) `BS.append` bs
	where
	bs = renegotiationInfoToByteString r
extensionToByteString (ExtensionECPointFormat pfs) = "\x00\x0b" `BS.append`
	lenToBS 2 (BS.length bs) `BS.append` bs
	where
	bs = ecPointFormatListToByteString pfs
extensionToByteString (ExtensionSessionTicketTLS bs) = "\x00\x23" `BS.append`
	lenToBS 2 (BS.length bs) `BS.append` bs
extensionToByteString ExtensionNextProtocolNegotiation = "\x33\x74\x00\x00"
extensionToByteString (ExtensionOthers (ExtensionTypeOthers t) bs) =
	word16ToBS t `BS.append` lenToBS 2 (BS.length bs) `BS.append` bs

word16ToBS :: Word16 -> BS.ByteString
word16ToBS w = BS.pack $ map fromIntegral [w `div` 256, w `mod` 256]
	
-- extensionToByteString e = error $ "not implemented yet: " ++ show e
-}
