修正点
======

HTTP PULL Client
----------------

### Plain

* pollの間隔を引数として渡せるようにする (Nothingも可能とする)
* pollの間隔を途中で変えられるようにする
* パスを送信ごとに変えられるようにする
	- XmlPusherクラスへの変更が必要
	- 送信データに送信データのタイプを指定できるようにするか
	- その場合、返信の必要性を指定するBool値をそこに含めることが可能かも

### TLS

HTTP PULL Server
----------------

### Plain

### TLS

HTTP PUSH
---------

### Plain

### TLS
