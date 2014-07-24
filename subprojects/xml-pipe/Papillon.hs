{-# LANGUAGE OverloadedStrings, TypeFamilies, QuasiQuotes #-}

module Papillon(parseXmlEvent) where

import Data.Char
import Data.ByteString.Char8 (ByteString, pack)
import Text.Papillon

import qualified Data.ByteString.Char8 as BSC

data XmlEvent
	= XEXmlDecl (Int, Int)
	| XESTag BSC.ByteString
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

nameStartChar :: Char = <isAlpha>

nameChar :: Char = <isAlphaNum>

name :: ByteString
	= sc:nameStartChar cs:(c:nameChar { c })*	{ pack $ sc : cs }

charData :: XmlEvent
	= '>' cds:(<(`notElem` "<&")>)*			{ XECharData $ pack cds }

xmlDecl :: XmlEvent
	= '<' '?' 'x' 'm' 'l' vi:versionInfo _:spaces? '?' _:eof
	{ XEXmlDecl vi }

versionInfo :: (Int, Int)
	= _:spaces 'v' 'e' 'r' 's' 'i' 'o' 'n' _:eq
		'"' v:versionNum '"'
	{ v }

eq :: () = _:spaces? '=' _:spaces?

versionNum :: (Int, Int)
	= '1' '.' d:<isDigit>+			{ (1, read d) }

sTag :: XmlEvent
	= '<' n:name _:spaces? _:eof		{ XESTag n }

eTag :: XmlEvent
	= '<' '/' n:name _:spaces? _:eof	{ XEETag n }
--	= '<' '/' n:name _:spaces?		{ XEETag n }

eof = !_

|]

instance Source ByteString where
	type Token ByteString = Char
	data Pos ByteString = NoPos
	getToken = BSC.uncons
	initialPos = NoPos
	updatePos _ _ = NoPos
