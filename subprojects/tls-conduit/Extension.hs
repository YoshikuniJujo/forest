{-# LANGUAGE TupleSections #-}

module Extension (Extensions, extensions) where

import Prelude hiding (take)

import Data.Conduit
import qualified Data.Conduit.List as List
import Data.Conduit.Binary

import Data.Word
import Data.ByteString.Lazy (toStrict)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS

import ServerName
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
	mlen <- maybeLen 2
	case mlen of
		Just len -> do
			body <- take len
			yield $ ExtensionOthers
				(extensionType $ toWord16 t) $ toStrict body
			parseExtension
		_ -> return ()

-- eachExtension :: Monad m => Conduit BS.ByteString m Extension
-- eachExtension = do

toWord16 :: LBS.ByteString -> Word16
toWord16 bs = let
	w1 = LBS.head bs
	w2 = LBS.head $ LBS.tail bs in
	fromIntegral w1 * 256 + fromIntegral w2

type Extensions = [Extension]

data Extension
	= ExtensionServerName ServerName
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
