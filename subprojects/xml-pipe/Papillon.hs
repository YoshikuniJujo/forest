{-# LANGUAGE OverloadedStrings, TypeFamilies, QuasiQuotes #-}

module Papillon(parseXmlEvent, XmlEvent(..)) where

import Data.Char
import Data.ByteString.Char8 (ByteString, pack)
import Text.Papillon

import qualified Data.ByteString.Char8 as BSC

data XmlEvent
	= XEXmlDecl (Int, Int)
	| XESTag BSC.ByteString [(BSC.ByteString, BSC.ByteString)]
	| XEETag BSC.ByteString
	| XECharData BSC.ByteString
	deriving Show

parseXmlEvent :: ByteString -> Maybe XmlEvent
parseXmlEvent = either (const Nothing) (Just . fst) . runError . xmlEvent . parse

[papillon|

source: ByteString

xmlEvent :: XmlEvent
	= st:sTag		{ st }
	/ et:eTag		{ et }
	/ cd:charData		{ cd }
	/ xd:xmlDecl		{ xd }

spaces = _:(' ' / '\t' / '\r' / '\n')+

nameStartChar :: Char = <(`elem` (":_" ++ ['a' .. 'z'] ++ ['A' .. 'Z']))>

nameChar :: Char
	= s:nameStartChar				{ s }
	/ <(`elem` ("-." ++ ['0' .. '9']))>

name :: ByteString
	= sc:nameStartChar cs:(c:nameChar { c })*	{ pack $ sc : cs }

attValue :: ByteString
	= '"' v:(<(`notElem` "<&\"")>)* '"'		{ pack v }
	/ '\'' v:(<(`notElem` "<&'")>)* '\''		{ pack v }

charData :: XmlEvent
	= '>' cds:(<(`notElem` "<&")>)*			{ XECharData $ pack cds }

xmlDecl :: XmlEvent
	= '<' '?' 'x' 'm' 'l' vi:versionInfo _:spaces? '?' _:eof
	{ XEXmlDecl vi }

versionInfo :: (Int, Int)
	= _:spaces 'v' 'e' 'r' 's' 'i' 'o' 'n' _:eq
		vn:('"' v:versionNum '"' { v } / '\'' v:versionNum '\'' { v })
	{ vn }

eq :: () = _:spaces? '=' _:spaces?

versionNum :: (Int, Int)
	= '1' '.' d:<isDigit>+				{ (1, read d) }

sTag :: XmlEvent
	= '<' n:name as:(_:spaces a:attribute { a })* _:spaces? _:eof
	{ XESTag n as }

attribute :: (ByteString, ByteString)
	= n:name _:eq v:attValue			{ (n, v) }

eTag :: XmlEvent
	= '<' '/' n:name _:spaces? _:eof	{ XEETag n }

eof = !_

|]

instance Source ByteString where
	type Token ByteString = Char
	data Pos ByteString = NoPos
	getToken = BSC.uncons
	initialPos = NoPos
	updatePos _ _ = NoPos
