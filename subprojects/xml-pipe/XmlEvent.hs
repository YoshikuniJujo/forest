module XmlEvent (xmlEvent, XmlEvent(..)) where

import Data.Pipe
import Data.Word8
import qualified Data.ByteString as BS

import Lexer
import Papillon

xmlEvent :: Monad m => Pipe BS.ByteString (Maybe XmlEvent) m ()
xmlEvent = sepTag =$= convert parseXmlEvent =$= filterP (maybe True notEmpty)

notEmpty :: XmlEvent -> Bool
notEmpty (XECharData cd) = not $ BS.all isSpace cd
notEmpty _ = True

convert :: Monad m => (a -> b) -> Pipe a b m ()
convert f = await >>= maybe (return ()) (\x -> yield (f x) >> convert f)

filterP :: Monad m => (a -> Bool) -> Pipe a a m ()
filterP p = await >>=
	maybe (return ()) (\x -> (if p x then yield x else return ()) >> filterP p)
