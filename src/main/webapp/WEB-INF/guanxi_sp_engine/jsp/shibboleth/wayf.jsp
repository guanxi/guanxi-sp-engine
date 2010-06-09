<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%
  String url = (String)request.getAttribute("wayfLocation");
  url += "?shire=" + (String)request.getAttribute("shire");
  url += "&target=" + (String)request.getAttribute("target");
  url += "&time=" + (String)request.getAttribute("time");
  url += "&providerId=" + (String)request.getAttribute("providerId");
%>
<html>
  <head>
    <meta http-equiv="refresh" content="0;url=<%= url %>">
  </head>
</html>
