{-# LANGUAGE TupleSections #-}

module Extension (Extensions, extensions) where

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
			sourceLbs body $= parseExtensions $$ await
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
	0 <- getLen 2
	yield ExtensionSessionTicketTLS
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

type Extensions = [Extension]

data Extension
	= ExtensionServerName ServerNameList
	| ExtensionRenegotiationInfo RenegotiationInfo
	| ExtensionEllipticCurve EllipticCurveList
	| ExtensionECPointFormat ECPointFormatList
	| ExtensionSessionTicketTLS
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
