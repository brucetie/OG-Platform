/**
 * Copyright (C) 2014 - present by OpenGamma Inc. and the OpenGamma group of companies
 * 
 * Please see distribution for license.
 */
package com.opengamma.provider.permission.impl;

import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.UnauthenticatedException;

import com.opengamma.core.user.UserPrincipals;
import com.opengamma.provider.permission.PermissionCheckProvider;
import com.opengamma.provider.permission.PermissionCheckProviderRequest;
import com.opengamma.provider.permission.PermissionCheckProviderResult;
import com.opengamma.util.ArgumentChecker;
import com.opengamma.util.auth.AuthUtils;
import com.opengamma.util.auth.ShiroPermission;

/**
 * An Apache Shiro permission that uses a {@code PermissionCheckProvider}.
 * <p>
 * This uses the underlying provider to check permissions.
 * See {@link ProviderBasedPermissionResolver} for public access.
 */
final class ProviderBasedPermission implements ShiroPermission {

  /**
   * The underlying provider.
   */
  private final PermissionCheckProvider _provider;
  /**
   * The permission string.
   */
  private final String _permissionString;

  /**
   * Creates an instance of the permission.
   * 
   * @param provider  the underlying permission check provider, not null
   * @param permissionString  the permission string, not null
   */
  ProviderBasedPermission(PermissionCheckProvider provider, String permissionString) {
    _provider = ArgumentChecker.notNull(provider, "provider");
    _permissionString = ArgumentChecker.notNull(permissionString, "permissionString");
  }

  //-------------------------------------------------------------------------
  // this permission is the permission I have
  // the other permission is the permission being checked
  @Override
  public boolean implies(Permission requiredPermission) {
    if (requiredPermission instanceof ProviderBasedPermission == false) {
      return false;
    }
    ProviderBasedPermission requiredPerm = (ProviderBasedPermission) requiredPermission;
    UserPrincipals user = (UserPrincipals) AuthUtils.getSubject().getSession().getAttribute(UserPrincipals.ATTRIBUTE_KEY);
    if (user == null) {
      return false;
    }
    return _provider.isPermitted(user.getAlternateIds(), user.getNetworkAddress(), requiredPerm._permissionString);
  }

  @Override
  public boolean checkImplies(Permission requiredPermission) {
    if (requiredPermission instanceof ProviderBasedPermission == false) {
      return false;
    }
    ProviderBasedPermission requiredPerm = (ProviderBasedPermission) requiredPermission;
    UserPrincipals user = (UserPrincipals) AuthUtils.getSubject().getSession().getAttribute(UserPrincipals.ATTRIBUTE_KEY);
    if (user == null) {
      throw new UnauthenticatedException("Permission denied: User not logged in: " + requiredPermission);
    }
    PermissionCheckProviderRequest request = PermissionCheckProviderRequest.createGet(
        user.getAlternateIds(), user.getNetworkAddress(), requiredPerm._permissionString);
    PermissionCheckProviderResult result = _provider.isPermitted(request);
    result.checkErrors();
    return result.isPermitted(requiredPerm._permissionString);
  }

  //-------------------------------------------------------------------------
  @Override
  public boolean equals(Object obj) {
    if (obj instanceof ProviderBasedPermission) {
      ProviderBasedPermission other = (ProviderBasedPermission) obj;
      return _permissionString.equals(other._permissionString);
    }
    return false;
  }

  @Override
  public int hashCode() {
    return _permissionString.hashCode();
  }

  @Override
  public String toString() {
    return _permissionString;
  }

}
