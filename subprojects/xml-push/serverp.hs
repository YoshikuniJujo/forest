{-# LANGUAGE OverloadedStrings, PackageImports #-}

import Control.Monad
import "monads-tf" Control.Monad.Trans
import Control.Concurrent
import Control.Concurrent.STM
import Data.Maybe
import Data.Pipe
import Data.Pipe.List
import Data.Pipe.TChan
import Data.Pipe.ByteString
import System.IO
import Text.XML.Pipe
import Network
import Network.TigHTTP.Server
import Network.TigHTTP.Types

import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as LBS

main :: IO ()
main = do
	soc <- listenOn $ PortNumber 80
	forever $ do
		(h, _, _) <- accept soc
		void . forkIO $ do
			(r, w) <- run h
			void . forkIO $ runPipe_ $
				(fromTChan r :: Pipe () XmlNode IO ())
					=$= convert (xmlString . (: []))
					=$= toHandleLn stdout
			runPipe_ $ fromHandle stdin
				=$= xmlEvent
				=$= convert fromJust
				=$= xmlNode []
				=$= toTChan w

run :: Handle -> IO (TChan XmlNode, TChan XmlNode)
run h = do
	inc <- atomically newTChan
	otc <- atomically newTChan
	void . forkIO . runPipe_ $ talk h inc otc
	return (inc, otc)

talk h inc otc = do
	r <- lift $ getRequest h
	lift . print $ requestPath r
	requestBody r
		=$= xmlEvent
		=$= convert fromJust
		=$= xmlNode []
		=$= toTChan inc
	(fromTChan otc =$=) $ (await >>=) $ maybe (return ()) $ \n ->
		lift . putResponse h
			. (response :: LBS.ByteString -> Response Pipe Handle)
			$ LBS.fromChunks [xmlString [n]]
	talk h inc otc
