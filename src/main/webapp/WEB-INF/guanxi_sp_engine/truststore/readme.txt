This is the Engine's truststore. It holds the certificates of all entities that the Engine communicates with via HTTPS.
In the case of Guards, the Engine will auto trust them and probe for their certificates and automatically
add them to the truststore.
The Engine will auto create a truststore if it doesn't exist from the info in:
/WEB-INF/guanxi_sp_engine/config/spring/application/config.xml <TrustStore>