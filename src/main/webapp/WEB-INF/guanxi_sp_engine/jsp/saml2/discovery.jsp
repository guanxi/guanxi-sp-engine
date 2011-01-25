<html>
<head>
<% if (request.getAttribute("edsError") == null) { %>
  <meta http-equiv="REFRESH" content="0;url=<%= request.getAttribute("edsURL") %>">
<% } %>
</head>
<% if (request.getAttribute("edsError") != null) { %>
<body>
  <p><%= request.getAttribute("edsError") %></p>
</body>
<% } %>
</html>