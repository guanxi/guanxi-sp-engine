<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jstl/fmt" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
  <head>
    <title><fmt:message key="register.idp.page.title"/></title>
    <link rel="stylesheet" href="<%= request.getContextPath() %>/guanxi_sp/stylesheet/guanxi_sp.css" type="text/css">
    <style type="text/css">body {background-image: url(<%= request.getContextPath() %>/guanxi_sp/images/watermark.gif);}</style>
    </head>
  <body>
  <div id="requestForm" class="guanxiDiv" style="width:40%; height:70%; background-image:url(<%= request.getContextPath() %>/guanxi_sp/images/formback.gif);">
    <div style="padding:20px; margin: 0 auto;">
      <form:form method="post" commandName="registerIdP">
        <!-- Filename of the IdP -->
        <fmt:message key="register.idp.field.filename"/>:<br />
        <form:input path="filename" size="50"/>.xml
        <br /><form:errors path="filename" />
        <br /><br />

        <!-- entityID of the IdP -->
        <fmt:message key="register.idp.field.entityID"/>:<br />
        <form:input path="entityID" size="50"/>
        <br /><form:errors path="entityID" />
        <br /><br />

        <!-- AA of the IdP -->
        <fmt:message key="register.idp.field.aa"/>:<br />
        <form:input path="aa" size="50"/>
        <br /><form:errors path="aa" />
        <br /><br />

        <!-- X509 of the IdP -->
        <fmt:message key="register.idp.field.x509"/>:<br />
        <form:textarea path="x509" rows="20" cols="70" />
        <br /><form:errors path="x509" />
        <br /><br />

        <input type="submit" value="<fmt:message key="register.idp.submit.button"/>" />
      </form:form>
    </div>
   </div>
  </body>
</html>