HttpPush.hsに対する変更点
=========================

対応済
------

* data HttpPushArgsを作成する

予定
----

* 返答の必要がないXmlNodeを引数で指定する
	+ [x] 返答の必要があるかどうかを示す関数を引数に取る
	+ [ ] 返答の必要がないものに対しては自動で返答する
* domain名を引数で指定できるようにする
* 基準となるパスを引数で指定する
* 通信ごとに変化するパスの部分を引数で指定する