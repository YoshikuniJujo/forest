HttpPullTlsCl.hsに対する変更点
==============================

対応済
------

* 引数用のデータ型を作成する
* peyotlsのTChanのほうを利用するようにする
	+ スレッドを使うためにはTChan版が必要となる
* repair_polling.mdを参照のこと
	+ [x] サーバ側の変更
	+ [x] クライアント側の変更
* pollの間隔をサーバからのデータによって変えられるようにする
	+ [x] XmlNode -> Maybe Intを引数として取るようにし
	+ [x] makeHttpPull関数でTVar (Maybe Int)の値を作成する
	+ [x] TVar (Maybe Int)の値を受けとったXmlNodeによって変更していく
* パスを送信ごとに変えられるようにする
	+ [x] XmlNode -> BS.ByteString型の引数を追加する
	+ [x] 上記の関数によって得た値をパスに追加する

予定
----

* ポート番号を引数で指定できるようにする
