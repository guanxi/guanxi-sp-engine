<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jstl/fmt" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
  <head>
    <title><fmt:message key="register.guard.page.title"/></title>
    <link rel="stylesheet" href="<%= request.getContextPath() %>/guanxi_sp/stylesheet/guanxi_sp.css" type="text/css">
    <style type="text/css">body {background-image: url(<%= request.getContextPath() %>/guanxi_sp/images/watermark.gif );}</style>
    </head>
  <body>
  <div id="requestForm" class="guanxiDiv" style="width:40%; height:70%; background-image:url(<%= request.getContextPath() %>/guanxi_sp/images/formback.gif);">
    <div style="padding:20px; margin: 0 auto;">

      <form:form method="post" commandName="registerGuard">

        <!-- ID of the Guard -->
        <fmt:message key="register.guard.field.guardid"/><br />
        <form:input path="guardid" size="50"/>
        <br /><form:errors path="guardid" />
        <br /><br />

        <!-- Details for creating certificate -->

        <!-- The scheme, wether http or https -->
        <fmt:message key="register.guard.field.scheme"/><br />
        <form:select path="scheme" multiple="false">
          <form:option value="" label="--Please Select"/>
          <form:option value="http" label="HTTP"/>
          <form:option value="https" label="HTTPS"/>
        </form:select>
        <br /><form:errors path="scheme" />
        <br /><br />

        <!-- The port the application is running on -->
        <fmt:message key="register.guard.field.port"/><br />
        <form:input path="port" size="4"/>
        <br /><form:errors path="port" />
        <br /><br />

        <!-- The domain the Guard will work in -->
        <fmt:message key="register.guard.field.url"/><br />
        <form:input path="url" size="50"/>
        <br /><form:errors path="url" />
        <br /><br />

        <!-- The web application the Guard will protect -->
        <fmt:message key="register.guard.field.applicationName"/><br />
        <form:input path="applicationName" size="50"/>
        <br /><form:errors path="applicationName" />
        <br /><br />

        <!-- The unit of the domain -->
        <fmt:message key="register.guard.field.orgunit"/><br />
        <form:input path="orgunit" size="50"/>
        <br /><form:errors path="orgunit" />
        <br /><br />

        <!-- The organisation -->
        <fmt:message key="register.guard.field.org"/><br />
        <form:input path="org" size="50"/>
        <br /><form:errors path="org" />
        <br /><br />

        <!-- The city -->
        <fmt:message key="register.guard.field.city"/><br />
        <form:input path="city" size="50"/>
        <br /><form:errors path="city" />
        <br /><br />

        <!-- The locality -->
        <fmt:message key="register.guard.field.locality"/><br />
        <form:input path="locality" size="50"/>
        <br /><form:errors path="locality" />
        <br /><br />

        <!- The two letter country code -->
        <fmt:message key="register.guard.field.country"/><br />
        <form:input path="country" size="2"/>
        <br /><form:errors path="country" />
        <br /><br />

        <!-- Contact details for metadata -->

        <h1><fmt:message key="register.guard.label.contactdetails"/></h1><br />

        <fmt:message key="register.guard.field.contactCompany"/><br />
        <form:input path="contactCompany" size="50"/>
        <br /><form:errors path="contactCompany" />
        <br /><br />

        <fmt:message key="register.guard.field.contactGivenName"/><br />
        <form:input path="contactGivenName" size="50"/>
        <br /><form:errors path="contactGivenName" />
        <br /><br />

        <fmt:message key="register.guard.field.contactSurname"/><br />
        <form:input path="contactSurname" size="50"/>
        <br /><form:errors path="contactSurname" />
        <br /><br />

        <fmt:message key="register.guard.field.contactEmail"/><br />
        <form:input path="contactEmail" size="50"/>
        <br /><form:errors path="contactEmail" />
        <br /><br />

        <fmt:message key="register.guard.field.contactPhone"/><br />
        <form:input path="contactPhone" size="50"/>
        <br /><form:errors path="contactPhone" />
        <br /><br />

        <input type="submit" value="<fmt:message key="register.guard.submit.button"/>" />
        
      </form:form>

    </div>
   </div>
  </body>
</html>