{-# LANGUAGE OverloadedStrings #-}

module XmlCreate (xmlEvent, XmlEvent(..), xmlBegin, xmlNode) where

import Control.Applicative
import Control.Arrow
import Data.Pipe
import qualified Data.ByteString as BS

import XmlEvent

type QName = ((BS.ByteString, Maybe BS.ByteString), BS.ByteString)

data XmlNode
	= XmlStart QName [(QName, BS.ByteString)]
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

xmlNode :: Monad m => [(BS.ByteString, BS.ByteString)] -> Pipe XmlEvent XmlNode m ()
xmlNode nss = do
	mnd <- xmlNd nss
	case mnd of
		Just nd -> yield nd >> xmlNode nss
		_ -> return ()
{-
	mxe <- await
	case mxe of
		Just (XESTag n nss' atts) -> do
			Just nd <- xmlNd nss
			yield nd
		{-
			yield $ XmlNode (toQName (nss ++ nss') n)
				(map (first $ toQName (nss ++ nss')) atts) []
				-}
		Nothing -> return ()
		_ -> error "bad"
		-}

xmlNd :: Monad m =>
	[(BS.ByteString, BS.ByteString)] -> Pipe XmlEvent a m (Maybe XmlNode)
xmlNd nss = do
	mxe <- await
	case mxe of
		Just (XESTag n nss' atts) -> do
			nds <- xmlNds (nss' ++ nss)
			return . Just $ XmlNode (toQName (nss' ++ nss) n)
				(map (first $ toQName (nss' ++ nss)) atts) nds
		Just (XEETag n) -> return Nothing
		Just (XECharData cd) -> return . Just $ XmlCharData cd
		_ -> return Nothing
--		_ -> error $ "bad: " ++ show mxe

xmlNds :: Monad m => [(BS.ByteString, BS.ByteString)] -> Pipe XmlEvent a m [XmlNode]
xmlNds nss = do
	mxn <- xmlNd nss
	case mxn of
		Just xn -> (xn :) <$> xmlNds nss
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
