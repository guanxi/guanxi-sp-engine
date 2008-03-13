<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jstl/fmt" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
  <head><title><fmt:message key="sp.messge.page.title"/></title>
    <style type="text/css">
      <!--
      body {
        background-color: #FFFFFF;
        margin-left: 20px;
        margin-top: 20px;
        margin-right: 20px;
        margin-bottom: 20px;
        font-family:Verdana, Arial, Helvetica, sans-serif;
        background-image: url(<%= request.getContextPath() %>/guanxi_sp/images/watermark.gif);
      }
      -->
    </style>
  </head>
  <body>
  <div style="border:1px solid black; width:50%; height:20%; background-image:url(<%= request.getContextPath() %>/guanxi_sp/images/formback.gif); background-repeat:repeat-x repeat-y; margin: 0 auto;">
    <div style="padding:20px; margin: 0 auto;">
      <c:out value="${error}" /><br /><br />
      <c:out value="${message}" />
    </div>
   </div>

   <div style="width:50%; margin: 0 auto;">
     <div align="left"><strong>Guanxi@<fmt:message key="institution.display.name"/></strong></div>
   </div>
  </body>
</html>