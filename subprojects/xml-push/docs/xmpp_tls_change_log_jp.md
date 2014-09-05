XmppTls.hsに対する変更予定点
============================

対応済
------

* JID(自分と相手)を引数で渡すようにする
* cnonceをランダムにする
* 引数用のデータ型を作成する
* パスワードを引数で渡すようにする
* 使用するmechanismsを引数で渡せるようにする
* idにUUIDを使うようにする
* messageのほうのidにUUIDを使用する
* XMPP用の引数とTLS用の引数とを分けて(XmppArgs, TlsArgs)のようにすることを検討する
	- XMPP用の引数はXmpp.hsと共通で使えると思う
* TLSに関する値を引数で渡すようにする
	- certification authority
	- key
	- certificate chain
	- keyとcertificate chainはMaybe型またはリストにしておくか

* Xmpp型が保持する出力用の値を変更する
	+ (Pipe Mpi () (HandleMonad h) ())から
	+ (TChan (Either BS.ByteString (XmlNode, pt)))にする
	+ makeXmppでfromTChan wc =$= addRandom ...をforkIOで走らせる
* Xmpp型が保持する値にwantResponseを追加する
* Xmppの引数の型にwantResponse :: XmlNode -> Boolを追加する
* pushIdを変更する
	+ wantResponseがFalseの場合にwriteTChan wc (Left i)をする

予定
----
