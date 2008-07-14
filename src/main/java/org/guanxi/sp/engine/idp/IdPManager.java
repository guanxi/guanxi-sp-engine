/**
 * 
 */
package org.guanxi.sp.engine.idp;

import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import javax.servlet.ServletContext;

/**
 * This is responsible for managing the loaded IdP Metadata.
 * The following operations must be supported:
 * 
 * <ul>
 * 	<li>Adding new IdP Metadata</li>
 *  <li>Retrieving IdP Metadata by entityID</li>
 *  <li>Unloading loaded IdP Metadata</li>
 * </ul>
 * 
 * The IdP Metadata must be associated with the method of loading
 * the data. This is required because for periodic loading of
 * IdP Metadata the previous data must be unloaded to successfully
 * remove IdP entries that are no longer present in the current
 * Metadata.
 * 
 * A current potential bug is that if the metadata for an IdP is loaded
 * twice then removal of either set will remove the IdP metadata.
 * 
 * @author matthew
 */
public final class IdPManager {
	/**
	 * This is the key used to get the IdP out of the ServletContext.
	 */
	private static final String key = IdPManager.class.getName();
	/**
	 * This is the map of entityID to IdP Metadata, and this is
	 * the only place that the IdP Metadata is stored.
	 */
	private final Map<String, IdPMetadata> metadataByEntityID;
	/**
	 * This is the map of loaded source name and the entityIDs that
	 * have been loaded from that source.
	 */
	private final Map<String, Set<String>> entityIDBySource;
	
	/**
	 * This will return the IdPManager for this application.
	 * If there is no current IdPManager then this will create one.
	 * 
	 * @param context  This is the ServletContext which holds the IdPManager
	 * @return         This will return the IdPManager held by the ServletContext
	 */
	public static IdPManager getManager(ServletContext context) {
		IdPManager manager;
		
		if ( (manager = (IdPManager)context.getAttribute(key)) != null ) {
			return manager;
		}
		
		manager = new IdPManager();
		context.setAttribute(key, manager);
		
		return manager;
	}
	
	/**
	 * This creates an empty IdP Manager.
	 * This is private to ensure that the only way to access this
	 * class is through the {@link #getManager(ServletContext)} method.
	 */
	private IdPManager() {
		metadataByEntityID = new TreeMap<String, IdPMetadata>();
		entityIDBySource = new TreeMap<String, Set<String>>();
	}

	/**
	 * This appends metadata to the list of metadata loaded for this
	 * particular source. Existing metadata loaded for this source is
	 * retained.
	 * 
	 * @param source   This is a unique string that represents the source of the metadata.
	 * @param metadata This is the metadata that has been loaded from the source.
	 */
	public void addMetadata(String source, IdPMetadata... metadata) {
		String entityID;
		Set<String> entityIDList;
		
		if ( ! entityIDBySource.containsKey(source) ) {
			entityIDBySource.put(source, new TreeSet<String>());
		}
		entityIDList = entityIDBySource.get(source);
		
		for ( IdPMetadata currentMetadata : metadata ) {
			entityID = currentMetadata.getEntityID();
			metadataByEntityID.put(entityID, currentMetadata);
			entityIDList.add(entityID);
		}
	}
	
	/**
	 * This returns the metadata associated with a particular entityID.
	 * If the entityID is not associated with metadata then null is returned.
	 * 
	 * @param entityID   This is the entityID for the IdP whos metadata is being requested.
	 * @return           This will return the IdPMetadata for the IdP or null if there is no metadata for the IdP.
	 */
	public IdPMetadata getMetadata(String entityID) {
		return metadataByEntityID.get(entityID);
	}
	
	/**
	 * This will remove all metadata that has been loaded for a particular
	 * source. The record of entityIDs associated with that source is also
	 * cleared.
	 * 
	 * @param source This is a unique string that represents the source of the metadata.
	 */
	public void removeMetadata(String source) {
		if ( entityIDBySource.containsKey(source) ) {
			for ( String entityID : entityIDBySource.get(source) ) {
				metadataByEntityID.remove(entityID);
			}
			entityIDBySource.remove(source);
		}
	}
	
	/**
	 * This will remove any existing metadata from the indicated source,
	 * replacing it with the provided metadata.
	 * 
	 * @param source   This is a unique string that represents the source of the metadata.
	 * @param metadata This is the metadata that has been loaded from the source.
	 */
	public void setMetadata(String source, IdPMetadata... metadata) {
		String entityID;
		Set<String> entityIDList;

		removeMetadata(source);
		
		entityIDBySource.put(source, entityIDList = new TreeSet<String>());
		
		for ( IdPMetadata currentMetadata : metadata ) {
			entityID = currentMetadata.getEntityID();
			metadataByEntityID.put(entityID, currentMetadata);
			entityIDList.add(entityID);
		}
	}
}
