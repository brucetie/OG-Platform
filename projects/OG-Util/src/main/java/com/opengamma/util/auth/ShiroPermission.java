/**
 * Copyright (C) 2013 - present by OpenGamma Inc. and the OpenGamma group of companies
 *
 * Please see distribution for license.
 */
package com.opengamma.util.auth;

import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.Permission;

/**
 * An extension to the Apache Shiro {@code Permission} interface.
 * <p>
 * This extension supports the check operation which can throw exceptions.
 * This allows implementations to throw meaningful exceptions.
 * See {@link ShiroPermissionResolver} for public access to permissions.
 */
public interface ShiroPermission extends Permission {

  /**
   * Checks that this permission implies the required permission.
   * <p>
   * This object will be the permission of the subject user.
   * The specified permission is the one that is required.
   * This only differs from {@link #implies(Permission)} in that this
   * method is allowed to throw an exception if there was a problem
   * determining the permission status.
   * 
   * @param requiredPermission  the required permission, not null
   * @return true if implied, false if not implied or type not recognized
   * @throws AuthorizationException if an exception occurred while determining the result
   */
  boolean checkImplies(Permission requiredPermission);

}
