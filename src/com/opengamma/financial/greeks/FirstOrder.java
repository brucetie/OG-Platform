/**
 * Copyright (C) 2009 - 2010 by OpenGamma Inc.
 * 
 * Please see distribution for license.
 */
package com.opengamma.financial.greeks;

import com.opengamma.financial.pnl.Underlying;

/**
 * @author emcleod
 * 
 */
public class FirstOrder extends Order {
  private final Underlying _variable;

  public FirstOrder(final Underlying variable) {
    _variable = variable;
  }

  /*
   * (non-Javadoc)
   * 
   * @see
   * com.opengamma.financial.greeks.OrderClass#accept(com.opengamma.financial
   * .greeks.OrderClassVisitor)
   */
  @Override
  public <T> T accept(final OrderVisitor<T> visitor) {
    return visitor.visitFirstOrder();
  }

  /*
   * (non-Javadoc)
   * 
   * @see com.opengamma.financial.greeks.OrderClass#getOrderType()
   */
  @Override
  public OrderType getOrderType() {
    return OrderType.FIRST;
  }

  public Underlying getVariable() {
    return _variable;
  }

  /*
   * (non-Javadoc)
   * 
   * @see java.lang.Object#toString()
   */
  @Override
  public String toString() {
    return "FirstOrder[" + _variable + "]";
  }

  /*
   * (non-Javadoc)
   * 
   * @see java.lang.Object#hashCode()
   */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((_variable == null) ? 0 : _variable.hashCode());
    return result;
  }

  /*
   * (non-Javadoc)
   * 
   * @see java.lang.Object#equals(java.lang.Object)
   */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    final FirstOrder other = (FirstOrder) obj;
    if (_variable == null) {
      if (other._variable != null)
        return false;
    } else if (!_variable.equals(other._variable))
      return false;
    return true;
  }
}
