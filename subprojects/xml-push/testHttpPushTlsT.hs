import Control.Monad
import System.IO
import Network

import HttpPushTls

main :: IO ()
main = do
	soc <- listenOn $ PortNumber 80
	forever  $ do
		(sh, _, _) <- accept soc
		ch <- connectTo "localhost" $ PortNumber 8080
		testPusher (undefined :: HttpPushTls Handle) (Two ch sh)
			(HttpPushTlsArgs)
			True
