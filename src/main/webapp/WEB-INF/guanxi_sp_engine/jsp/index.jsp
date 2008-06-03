<%@ taglib prefix="fmt" uri="http://java.sun.com/jstl/fmt" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
  <head>
    <title><fmt:message key="engine.page.title"/></title>
      <style type="text/css">
        <!--
        body {
          background-color: #FFFFFF;
          margin-left: 20px;
          margin-top: 20px;
          margin-right: 20px;
          margin-bottom: 20px;
          font-family:Verdana, Arial, Helvetica, sans-serif;
          background-image: url(images/watermark.gif);
        }
        -->
      </style>
  </head>
  <body>
    <div style="border:1px solid black; width:50%; height:20%; background-image:url(images/formback.gif); background-repeat:repeat-x repeat-y; margin: 0 auto;">
      <div style="padding:20px; margin: 0 auto;">
        <fmt:message key="engine.page.text"/><br/><br/>
        <a href="register/guard"><fmt:message key="register.guard.link"/></a><br/><br/>
        <a href="register/idp"><fmt:message key="register.idp.link"/></a>
      </div>
     </div>

    <br><br>

    <div style="border:1px solid black; width:50%; height:20%; background-image:url(images/formback.gif); background-repeat:repeat-x repeat-y; margin: 0 auto;">
      <div style="padding:20px; margin: 0 auto;">
        <fmt:message key="engine.page.doc.text"/><br><br>
        <a href="http://www.guanxi.uhi.ac.uk/index.php/Service_Provider"><fmt:message key="engine.page.doc.link.text"/></a><br><br>
      </div>
    </div>

    <br><br>

     <div style="width:50%; margin: 0 auto;">
       <div align="left"><strong>Guanxi@<fmt:message key="institution.display.name"/></strong></div>
     </div>
  </body>
</html>
