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
public class SecondOrder extends Order {
  private final Underlying _variable;

  public SecondOrder(final Underlying variable) {
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
    return visitor.visitSecondOrder();
  }

  /*
   * (non-Javadoc)
   * 
   * @see com.opengamma.financial.greeks.OrderClass#getOrderType()
   */
  @Override
  public OrderType getOrderType() {
    return OrderType.SECOND;
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
    return "SecondOrder[" + _variable + "]";
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
    final SecondOrder other = (SecondOrder) obj;
    if (_variable == null) {
      if (other._variable != null)
        return false;
    } else if (!_variable.equals(other._variable))
      return false;
    return true;
  }

}
