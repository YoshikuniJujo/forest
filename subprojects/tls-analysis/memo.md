関数の仕様に関するメモ
======================

mkClient.hs
-----------

mkClient.hsを改良して以下のような形に直したい。

	main = do
		tls <- openTls crt key
		tPut tls request
		tGetLine tls >>= BS.hPut stdout
		tGet 3 tls >>= BS.hPut stdout

	request :: BS.ByteString
	request = "GET / HTTP/1.1\r\n" +++ ...

### そのためには、まず

mkClient.hsのhandshake部分をひとつの関数としてくくり出そう。

conduitの枠組みへの対応
-----------------------

上記ができたら次は以下のような形を試みる。

tlsClientSource :: Handle -> Source m ByteString
tlsServerSource :: Handle -> Source m ByteString
