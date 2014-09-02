import System.IO
import Network

import XmppTls

main :: IO ()
main = do
	h <- connectTo "localhost" $ PortNumber 5222
	testPusher (undefined :: XmppTls Handle) (One h) ()
