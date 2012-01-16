/**
 * Copyright (C) 2012 - present by OpenGamma Inc. and the OpenGamma group of companies
 *
 * Please see distribution for license.
 */
package com.opengamma.web.server.push.rest;

import com.opengamma.web.server.push.LongPollingServlet;
import com.sun.jersey.api.core.ExtendedUriInfo;
import com.sun.jersey.api.core.HttpContext;
import com.sun.jersey.spi.container.ContainerRequest;

import javax.ws.rs.core.MultivaluedMap;
import java.security.Principal;
import java.util.List;

/**
 * Helper methods for the subscription filters.
 */
/* package */ class FilterUtils {

  private FilterUtils() {
  }

  /**
   * Returns the client ID from a request.
   * @param request The request
   * @param httpContext The HTTP context of the request
   * @return The client ID extracted from the request.  For GET requests the ID comes from the {@code clientId}
   * query parameter and for POST requests it's a form parameter.
   */
  /* package */ static String getClientId(ContainerRequest request, HttpContext httpContext) {
    List<String> clientIds = null;
    ExtendedUriInfo uriInfo = httpContext.getUriInfo();
    if (request.getMethod().equals("GET")) {
      // try to get the client ID from the query params (for a GET request)
      MultivaluedMap<String, String> queryParameters = uriInfo.getQueryParameters();
      clientIds = queryParameters.get(LongPollingServlet.CLIENT_ID);
    } else if (request.getMethod().equals("POST")) {
      // try to get the client ID from the form params (it's a POST)
      clientIds = httpContext.getRequest().getFormParameters().get(LongPollingServlet.CLIENT_ID, String.class);
    }
    if (clientIds == null || clientIds.size() != 1) {
      return null;
    } else {
      return clientIds.get(0);
    }
  }

  /**
   * Returns the user ID from a request's user principal.
   * TODO this doesn't do anything at the moment, we have no user logins
   * @param httpContext The HTTP context
   * @return The user ID from the request
   */
  /* package */ static String getUserId(HttpContext httpContext) {
    Principal userPrincipal = httpContext.getRequest().getUserPrincipal();
    if (userPrincipal == null) {
      // TODO reinstate this if / when we have user logins
      /*s_logger.debug("No user principal, not subscribing, url: {}", url);
     return response;*/
      return null;
    } else {
      return userPrincipal.getName();
    }
  }
}
