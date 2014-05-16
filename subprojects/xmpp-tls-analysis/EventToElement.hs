{-# LANGUAGE OverloadedStrings, RankNTypes #-}

module EventToElement (
	eventToElementAll,
	eventToElement,
	showElement,
	convert,
) where

import Data.Conduit

-- import Control.Arrow
import Control.Applicative
import Data.XML.Types
-- import Data.Text (Text)
import qualified Data.Text as T

import Control.Monad.IO.Class

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

eventToElementAll :: (Monad m, MonadIO m) => Conduit Event m Element
eventToElementAll = do
	mev <- await
	case mev of
		Just EventBeginDocument -> eventToElementAll
		Just (EventBeginElement (Name "stream" _ _) _) -> eventToElementAll
		Just (EventBeginElement nm ats) -> do
			mel <- toElement nm ats
			case mel of
				Just el -> do
					yield el
					eventToElementAll
				_ -> return ()
		Just (EventEndElement (Name "stream" _ _)) ->
			liftIO $ putStrLn "end stream"
		Just ev -> error $ "eventToElementAll: bad: " ++ show ev
		_ -> return ()

eventToElement :: Monad m => Conduit Event m Element
eventToElement = do
	mev <- await
	case mev of
		Just (EventBeginElement nm ats) -> do
			mel <- toElement nm ats
			case mel of
				Just el -> do
					yield el
					eventToElement
				_ -> return ()
		Just ev -> error $ "bad: " ++ show ev
		_ -> return ()

toElement :: Monad m => Name -> [(Name, [Content])] ->
	Consumer Event m (Maybe Element)
toElement nm ats = do
	mev <- await
	case mev of
		Just ev -> do
			ret <- Element nm ats <$> toNodeList nm ev
			return $ Just ret
		_ -> return Nothing

toNodeList :: Monad m => Name -> Event -> Consumer Event m [Node]
toNodeList nm (EventEndElement n)
	| nm == n = return []
	| otherwise = error "not match tag names"
toNodeList nm (EventContent c) = do
	mev <- await
	case mev of
		Just ev -> (NodeContent c :) <$> toNodeList nm ev
		_ -> return [NodeContent c]
toNodeList nm0 (EventBeginElement nm ats) = do
	mel <- toElement nm ats
	case mel of
		Just el -> do
			mev <- await
			case mev of
				Just ev -> (NodeElement el :) <$> toNodeList nm0 ev
				_ -> return [NodeElement el]
		_ -> return []
toNodeList _ _ = error "not implemented"

convert :: Monad m => (i -> o) -> Conduit i m o
convert f = do
	mx <- await
	case mx of
		Just x -> yield $ f x
		_ -> return ()

{-
testEventList :: [Event]
testEventList = [
	EventBeginElement hello [],
	EventContent $ ContentText "world",
	EventEndElement hello,

	EventBeginElement (name "yoshio") [],
	EventBeginElement (name "j") [],
	EventContent $ ContentText "hacker",
	EventEndElement (name "j"),
	EventEndElement (name "yoshio")
 ]

hello :: Name
hello = Name "hello" Nothing Nothing

name :: Text -> Name
name n = Name n Nothing Nothing

eventListToElement :: [Event] -> (Element, [Event])
eventListToElement (EventBeginElement name attrs : rest) =
	first (Element name attrs) $ eventListToNodeList rest
eventListToElement _ = error "Not element"

eventListToNodeList :: [Event] -> ([Node], [Event])
eventListToNodeList [] = ([], [])
eventListToNodeList (EventEndElement _ : rest) = ([], rest)
eventListToNodeList (EventContent cnt : rest) =
	first (NodeContent cnt :) $ eventListToNodeList rest
eventListToNodeList evs@(EventBeginElement _ _ : _) =
	(NodeElement elm : nds, evs'')
	where
	(elm, evs') = eventListToElement evs
	(nds, evs'') = eventListToNodeList evs'
eventListToNodeList _ = error "eventListToNodeList: not implemented yet"
-}

showElement :: Element -> BS.ByteString
showElement (Element nm ats []) =
	"<" +++ showNameOpen nm +++ showAttributeList ats +++ "/>"
showElement (Element nm ats nds) =
	"<" +++ showNameOpen nm +++ showAttributeList ats +++ ">" +++
	BS.concat (map showNode nds) +++ "</" +++ showName nm +++ ">"

showName, showNameOpen :: Name -> BS.ByteString
showName (Name n _ (Just np)) =
	BSC.pack (T.unpack np) +++ ":" +++ BSC.pack (T.unpack n)
-- showName (Name n (Just ns) _) = -- "{" ++ T.unpack ns ++ "}" ++ T.unpack n
--	T.unpack n ++ " " ++ "xmlns=\"" ++ T.unpack ns ++ "\""
showName (Name n _ _) = BSC.pack $ T.unpack n

showNameOpen (Name n _ (Just np)) =
	BSC.pack (T.unpack np) +++ ":" +++ BSC.pack (T.unpack n)
showNameOpen (Name n (Just ns) _) =
	BSC.pack (T.unpack n) +++ " " +++ "xmlns=\"" +++
		BSC.pack (T.unpack ns) +++ "\""
showNameOpen (Name n _ _) = BSC.pack (T.unpack n)

showAttributeList :: [(Name, [Content])] -> BS.ByteString
showAttributeList = BS.concat . map ((" " +++) . showAttribute)

showAttribute :: (Name, [Content]) -> BS.ByteString
showAttribute (n, cs) =
	showName n +++ "=\"" +++ BS.concat (map showContent cs) +++ "\""

showContent :: Content -> BS.ByteString
showContent (ContentText t) = BSC.pack (T.unpack t)
showContent _ = error "EventListToNodeList.showContent: not implemented"

showNode :: Node -> BS.ByteString
showNode (NodeElement e) = showElement e
showNode (NodeContent c) = showContent c
showNode (NodeComment c) = "<!-- " +++ BSC.pack (T.unpack c) +++ "-->"
showNode _ = error "EventListToNodeList.showNode: not implemented"

(+++) :: BS.ByteString -> BS.ByteString -> BS.ByteString
(+++) = BS.append
