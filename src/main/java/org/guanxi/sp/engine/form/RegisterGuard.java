//: "The contents of this file are subject to the Mozilla Public License
//: Version 1.1 (the "License"); you may not use this file except in
//: compliance with the License. You may obtain a copy of the License at
//: http://www.mozilla.org/MPL/
//:
//: Software distributed under the License is distributed on an "AS IS"
//: basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//: License for the specific language governing rights and limitations
//: under the License.
//:
//: The Original Code is Guanxi (http://www.guanxi.uhi.ac.uk).
//:
//: The Initial Developer of the Original Code is Alistair Young alistair@codebrane.com
//: All Rights Reserved.
//:

package org.guanxi.sp.engine.form;

/**
 * Backing object for the Register Guard form
 */
public class RegisterGuard {
  private String guardid = null;
  private String scheme = null;
  private String port = null;
  private String url = null;
  private String applicationName = null;
  private String orgunit = null;
  private String org = null;
  private String city = null;
  private String locality = null;
  private String country = null;
  private String contactCompany = null;
  private String contactGivenName = null;
  private String contactSurname = null;
  private String contactEmail = null;
  private String contactPhone = null;

  public RegisterGuard() {
  }
  
  public void setGuardid(String guardid) {
    this.guardid = guardid;
  }

  public String getGuardid() {
    return guardid;
  }

  public String getScheme() {
    return scheme;
  }

  public String getPort() {
    return port;
  }

  public String getUrl() {
    return url;
  }

  public String getApplicationName() {
    return applicationName;
  }

  public String getOrgunit() {
    return orgunit;
  }

  public String getOrg() {
    return org;
  }

  public String getCity() {
    return city;
  }

  public String getLocality() {
    return locality;
  }

  public String getCountry() {
    return country;
  }

  public String getContactCompany() {
    return contactCompany;
  }

  public String getContactGivenName() {
    return contactGivenName;
  }

  public String getContactSurname() {
    return contactSurname;
  }

  public String getContactEmail() {
    return contactEmail;
  }

  public String getContactPhone() {
    return contactPhone;
  }

  public void setScheme(String scheme) {
    this.scheme = scheme;
  }

  public void setPort(String port) {
    this.port = port;
  }

  public void setUrl(String url) {
    this.url = url;
  }

  public void setApplicationName(String applicationName) {
    this.applicationName = applicationName;
  }

  public void setOrgunit(String orgunit) {
    this.orgunit = orgunit;
  }

  public void setOrg(String org) {
    this.org = org;
  }

  public void setCity(String city) {
    this.city = city;
  }

  public void setLocality(String locality) {
    this.locality = locality;
  }

  public void setCountry(String country) {
    this.country = country;
  }

  public void setContactCompany(String contactCompany) {
    this.contactCompany = contactCompany;
  }

  public void setContactGivenName(String contactGivenName) {
    this.contactGivenName = contactGivenName;
  }

  public void setContactSurname(String contactSurname) {
    this.contactSurname = contactSurname;
  }

  public void setContactEmail(String contactEmail) {
    this.contactEmail = contactEmail;
  }

  public void setContactPhone(String contactPhone) {
    this.contactPhone = contactPhone;
  }
}
