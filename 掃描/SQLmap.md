# SQLmap 參數
|語法|用途|例子|
|---|---|---|
|-u|必須提供其中一個目標|-u url|
|--cookie=COOKIE|指定 HTTP Cookie 標頭值|--cookie="PHPSESSID"|
|--batch|永遠不要詢問使用者輸入，使用預設行為| -batch|
|--data|通過 POST 送出的資料字串 |--data="id=1&Submit=Submit" |
|-D|直接連線至資料庫|-D dvwa|
|--dbs|列舉資料庫名稱|--dbs|
|--durp|資料庫表格內容|--durp|
