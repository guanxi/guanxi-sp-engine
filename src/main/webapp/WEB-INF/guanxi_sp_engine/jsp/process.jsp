<%@ page import="java.util.Locale"%>
<%@ page import="java.util.ResourceBundle"%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix='c' uri='http://java.sun.com/jstl/core_rt' %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jstl/fmt" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %> 
<%
  ResourceBundle common = ResourceBundle.getBundle("messages.common", new Locale(request.getHeader("Accept-Language")));
  ResourceBundle msg = ResourceBundle.getBundle("messages.sp", new Locale(request.getHeader("Accept-Language")));
%>
<html>
  <head><title><%= msg.getString("error.page.title")%></title>
    <style type="text/css">
      <!--
      body {
        background-color: #FFFFFF;
        margin-left: 20px;
        margin-top: 20px;
        margin-right: 20px;
        margin-bottom: 20px;
        font-family:Verdana, Arial, Helvetica, sans-serif;
        background-image: url(<%= request.getContextPath() %>/guanxi_sp/images/watermark.gif );
      }
      td {
        font: 8pt Arial;
      }
      td.green {
        background-color: #AAFFAA;
      }
      td.red {
        background-color: #FFAAD4;
      }
      -->
    </style>
    <meta http-equiv="refresh" content="1"/>
  </head>
  <body>
  <div style="border:1px solid black; width:50%; height:20%; background-image:url(<%= request.getContextPath() %>/guanxi_sp/images/formback.gif); background-repeat:repeat-x repeat-y; margin: 0 auto;">
    <div style="padding:20px; margin: 0 auto;">
      <center>
        <p>Please Wait</p>
        <table width='100%' cellspacing='1' cellpadding='0' border='0'>
		  <tr>
		    <c:forEach begin="1" end="100" step="25" var="i">
              <c:if test="${i < percent}">
                <td class='green' nowrap='nowrap'>&nbsp;</td>
              </c:if>
              <c:if test="${i >= percent}">
                <td class='red' nowrap='nowrap'>&nbsp;</td>
              </c:if>
            </c:forEach>
          </tr>
        </table>
        <p>${text}</p>
      </center>
    </div>
   </div>

   <div style="width:50%; margin: 0 auto;">
     <div align="left"><strong>Guanxi@<%= common.getString("institution.display.name")%></strong></div>
   </div>
  </body>
</html>