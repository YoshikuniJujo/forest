import System.IO
import Network

import HttpPushTls

main :: IO ()
main = do
	ch <- connectTo "localhost" $ PortNumber 80
	soc <- listenOn $ PortNumber 8080
	(sh, _, _) <- accept soc
	testPusher (undefined :: HttpPushTls Handle) (Two ch sh) ()
