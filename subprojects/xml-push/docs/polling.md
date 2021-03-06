pollingの仕様
=============

1. 末端から幹へとpollが送られる
2. pendingされた出力が存在すればそれが返される
3. 無ければoadrResponseが返される。5へ
4. 2の応答が終了した段階でoadrResponse以外の応答であれば1へ
5. 定期的なpollへもどる

* 幹は末端からの応答を得るまでは次のpollを無視する
	+ 無視された場合、末端はどのように動作するべきか?
	+ 無視される可能性があるのは定期的なpollのみだと思われる
	+ しかし無視されるとしてもHTTPレベルでの返答は必要かと思うが?
	+ それとも完全な無視もあり得ると考えるべきか?
	+ 完全な無視があり得るとするとタイムアウトを実装する必要がある

末端の動作
----------

* 現在のような単純な実装では難しい
* pollingによって得たデータを読み込みチャンネルに流してやる必要がある
* pollingによって得たデータとそれ以外のデータとは混線しないだろうか
	+ 幹側がデータ処理中に来たpollを無視してくれれば問題ないと思われるが

* タイムアウトはtighttpのレベルで実装する必要がありそうだ
* 時計を刻む部分と実際にpollを送る部分とは別スレッドにする必要があるだろう

* とりあえず、まずはタイムアウトなしの実装を試る
	+ つまり、応答を返す前にpollが発生するというケースを考慮しない実装とする

* やはりpollを完全に無視するという機能には問題がある。
* pollへの返答を遅らせるか、またはHTTPレベルでの返答はするようにしないと
	+ pollに対する返答なのか、それ以外に対する返答なのかが不明になると思う

* 別スレッドで行っているかぎり難しいか

* ロックを取り合いするようにする必要がある
	+ つまりpollとそれ以外の出力はロックを取得してから送信し
	+ 受信またはタイムアウト後にロックを開放する
	+ TChanかTMVarあたりでロックは実装できるだろう
