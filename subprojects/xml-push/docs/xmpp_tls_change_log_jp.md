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

予定
----

* TLSに関する値を引数で渡すようにする
	- certification authority
	- key
	- certificate chain
* XMPP用の引数とTLS用の引数とを分けて(XmppArgs, TlsArgs)のようにすることを検討する
	- XMPP用の引数はXmpp.hsと共通で使えると思う
