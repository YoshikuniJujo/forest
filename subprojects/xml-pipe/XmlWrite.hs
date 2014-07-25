{-# LANGUAGE OverloadedStrings #-}

module XmlWrite (toByteString) where

import Control.Arrow

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

import XmlCreate

toByteString :: [XmlNode] -> BS.ByteString
toByteString = BS.concat . map eventToS . toEvent

toEvent :: [XmlNode] -> [XmlEvent]
toEvent [] = []
toEvent (XmlDecl v : ns) = XEXmlDecl v : toEvent ns
toEvent (XmlStart ((q, _), n) nss atts : ns) =
	XESTag (q, n) nss (map (first $ first fst) atts) : toEvent ns
toEvent (XmlNode ((q, _), n) nss atts ns : ns') =
	XESTag (q, n) nss (map (first $ first fst) atts) :
		toEvent ns ++ [XEETag (q, n)] ++ toEvent ns'
toEvent (XmlCharData cd : ns) = XECharData cd : toEvent ns

eventToS :: XmlEvent -> BS.ByteString
eventToS (XEXmlDecl (j, n)) = BS.concat [
	"<?xml version='", BSC.pack $ show j, ".",  BSC.pack $ show n, "'?>" ]
eventToS (XESTag qn nss atts) = BS.concat [
	"<", qNameToS qn,
	BS.concat $ map nsToS nss,
	BS.concat $ map attToS atts, ">" ]
eventToS (XEETag qn) = BS.concat ["</", qNameToS qn, ">"]
eventToS (XEEmptyElemTag qn nss atts) = BS.concat [
	"<", qNameToS qn,
	BS.concat $ map nsToS nss,
	BS.concat $ map attToS atts, "/>" ]
eventToS (XECharData cd) = cd

qNameToS :: (BS.ByteString, BS.ByteString) -> BS.ByteString
qNameToS ("", n) = n
qNameToS (q, n) = BS.concat [q, ":", n]

nsToS :: (BS.ByteString, BS.ByteString) -> BS.ByteString
nsToS ("", s) = BS.concat [" xmlns='", s, "'"]
nsToS (ns, s) = BS.concat [" xmlns:", ns, "='", s, "'"]

attToS :: ((BS.ByteString, BS.ByteString), BS.ByteString) -> BS.ByteString
attToS (qn, v) = BS.concat [" ", qNameToS qn, "='", v, "'"]
