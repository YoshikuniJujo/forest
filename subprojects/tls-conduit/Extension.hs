module Extension (Extensions, extensions) where

import Prelude hiding (take)

import Data.Conduit
import Data.Conduit.Binary

import Data.ByteString.Lazy (toStrict)
import qualified Data.ByteString as BS

import Tools

extensions :: Monad m => Consumer BS.ByteString m (Maybe Extensions)
extensions = do
	mlen <- maybeLen 2
	case mlen of
		Just len -> do
			body <- take len
			return $ Just [ExtensionOthers $ toStrict body]
		_ -> return Nothing

-- parseExtensions :: Monad m => Conduit BS.ByteString m Extensions

-- parseExtension :: Monad m => Conduit BS.ByteString m Extension
-- parseExtension = do

type Extensions = [Extension]

data Extension
	= ExtensionOthers BS.ByteString
	deriving Show
