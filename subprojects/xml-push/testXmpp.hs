import System.IO
import Network

import Xmpp

main :: IO ()
main = do
	h <- connectTo "localhost" $ PortNumber 5222
	testPusher (undefined :: Xmpp Handle) (One h) ()
