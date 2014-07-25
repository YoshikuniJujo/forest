{-# LANGUAGE OverloadedStrings #-}

module XmlCreate (
	xmlEvent, XmlEvent(..), XmlNode, xmlBegin, xmlNode) where

import Control.Applicative
import Control.Arrow
import Data.Pipe
import qualified Data.ByteString as BS

import XmlEvent

type QName = ((BS.ByteString, Maybe BS.ByteString), BS.ByteString)

data XmlNode
	= XmlDecl (Int, Int)
	| XmlStart QName [(QName, BS.ByteString)]
	| XmlEnd QName
	| XmlNode QName [(QName, BS.ByteString)] [XmlNode]
	| XmlCharData BS.ByteString
	deriving Show

toQName ::
	[(BS.ByteString, BS.ByteString)] -> (BS.ByteString, BS.ByteString) -> QName
toQName nss (q, n) = ((q, lookup q nss), n)

xmlBegin :: Monad m => Pipe XmlEvent XmlNode m [(BS.ByteString, BS.ByteString)]
xmlBegin = do
	mxe <- await
	case mxe of
		Just (XESTag n nss atts) -> do
			yield $ XmlStart (toQName nss n)
				(map (first $ toQName nss) atts)
			return nss
		Nothing -> return []
		_ -> xmlBegin

xmlNode :: Monad m =>
	[(BS.ByteString, BS.ByteString)] -> Pipe XmlEvent XmlNode m Bool
xmlNode nss = do
	mnd <- xmlNd nss
	case mnd of
		Right nd -> yield nd >> xmlNode nss
		Left (XEXmlDecl _) -> return True
		_ -> return False

xmlNd :: Monad m =>
	[(BS.ByteString, BS.ByteString)] -> Pipe XmlEvent a m (Either XmlEvent XmlNode)
xmlNd nss = do
	mxe <- await
	case mxe of
		Just (XESTag n nss' atts) -> do
			nds <- xmlNds (nss' ++ nss)
			return . Right $ XmlNode (toQName (nss' ++ nss) n)
				(map (first $ toQName (nss' ++ nss)) atts) nds
--		Just (XEETag n) -> return $ Left (XEE
		Just (XECharData cd) -> return . Right $ XmlCharData cd
--		Just (XEXmlDecl v) -> return . Just $ XmlDecl v
		Just xe -> return $ Left xe
		_ -> error "bad"
--		_ -> error $ "bad: " ++ show mxe

xmlNds :: Monad m => [(BS.ByteString, BS.ByteString)] -> Pipe XmlEvent a m [XmlNode]
xmlNds nss = do
	mxn <- xmlNd nss
	case mxn of
		Right xn -> (xn :) <$> xmlNds nss
		_ -> return []
{-
	mxe <- await
	case mxe of
		Just (XESTag n nss' atts) -> do
			nds <- xmlNds nss
			return . (: nds) $ XmlNode (toQName (nss ++ nss') n)
				(map (first $ toQName (nss ++ nss')) atts) []
		_ -> return []
		-}
