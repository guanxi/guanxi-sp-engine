<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%
  String url = (String)request.getAttribute("wbsso_endpoint");
  url += "?SAMLEncoding=urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE";
  url += "&SAMLRequest=" + (String)request.getAttribute("SAMLRequest");
  if (request.getAttribute("RelayState") != null) {
    url += "&RelayState=" + (String)request.getAttribute("RelayState");
  }
%>
<html>
  <head>
    <meta http-equiv="refresh" content="0;url=<%= url %>">
  </head>
</html>