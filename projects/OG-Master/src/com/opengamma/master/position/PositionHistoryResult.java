/**
 * Copyright (C) 2009 - present by OpenGamma Inc. and the OpenGamma group of companies
 *
 * Please see distribution for license.
 */
package com.opengamma.master.position;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.joda.beans.BeanBuilder;
import org.joda.beans.BeanDefinition;
import org.joda.beans.JodaBeanUtils;
import org.joda.beans.MetaProperty;
import org.joda.beans.impl.direct.DirectBeanBuilder;
import org.joda.beans.impl.direct.DirectMetaPropertyMap;

import com.opengamma.OpenGammaRuntimeException;
import com.opengamma.master.AbstractHistoryResult;
import com.opengamma.util.PublicSPI;

/**
 * Result providing the history of a position.
 * <p>
 * The returned documents may be a mixture of versions and corrections.
 * The document instant fields are used to identify which are which.
 * See {@link PositionHistoryRequest} for more details.
 */
@PublicSPI
@BeanDefinition
public class PositionHistoryResult extends AbstractHistoryResult<PositionDocument> {

  /**
   * Creates an instance.
   */
  public PositionHistoryResult() {
  }

  /**
   * Creates an instance from a collection of documents.
   * 
   * @param coll  the collection of documents to add, not null
   */
  public PositionHistoryResult(Collection<PositionDocument> coll) {
    super(coll);
  }

  //-------------------------------------------------------------------------
  /**
   * Gets the returned positions from within the documents.
   * 
   * @return the positions, not null
   */
  public List<ManageablePosition> getPositions() {
    List<ManageablePosition> result = new ArrayList<ManageablePosition>();
    if (getDocuments() != null) {
      for (PositionDocument doc : getDocuments()) {
        result.add(doc.getPosition());
      }
    }
    return result;
  }

  /**
   * Gets the first position, or null if no documents.
   * 
   * @return the first position, null if none
   */
  public ManageablePosition getFirstPosition() {
    return getDocuments().size() > 0 ? getDocuments().get(0).getPosition() : null;
  }

  /**
   * Gets the single result expected from a query.
   * <p>
   * This throws an exception if more than 1 result is actually available.
   * Thus, this method implies an assumption about uniqueness of the queried position.
   * 
   * @return the matching position, not null
   * @throws IllegalStateException if no position was found
   */
  public ManageablePosition getSingleSecurity() {
    if (getDocuments().size() != 1) {
      throw new OpenGammaRuntimeException("Expecting zero or single resulting match, and was " + getDocuments().size());
    } else {
      return getDocuments().get(0).getPosition();
    }
  }

  //------------------------- AUTOGENERATED START -------------------------
  ///CLOVER:OFF
  /**
   * The meta-bean for {@code PositionHistoryResult}.
   * @return the meta-bean, not null
   */
  @SuppressWarnings("unchecked")
  public static PositionHistoryResult.Meta meta() {
    return PositionHistoryResult.Meta.INSTANCE;
  }
  static {
    JodaBeanUtils.registerMetaBean(PositionHistoryResult.Meta.INSTANCE);
  }

  @Override
  public PositionHistoryResult.Meta metaBean() {
    return PositionHistoryResult.Meta.INSTANCE;
  }

  @Override
  protected Object propertyGet(String propertyName, boolean quiet) {
    return super.propertyGet(propertyName, quiet);
  }

  @Override
  protected void propertySet(String propertyName, Object newValue, boolean quiet) {
    super.propertySet(propertyName, newValue, quiet);
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (obj != null && obj.getClass() == this.getClass()) {
      return super.equals(obj);
    }
    return false;
  }

  @Override
  public int hashCode() {
    int hash = 7;
    return hash ^ super.hashCode();
  }

  //-----------------------------------------------------------------------
  /**
   * The meta-bean for {@code PositionHistoryResult}.
   */
  public static class Meta extends AbstractHistoryResult.Meta<PositionDocument> {
    /**
     * The singleton instance of the meta-bean.
     */
    static final Meta INSTANCE = new Meta();

    /**
     * The meta-properties.
     */
    private final Map<String, MetaProperty<?>> _metaPropertyMap$ = new DirectMetaPropertyMap(
      this, (DirectMetaPropertyMap) super.metaPropertyMap());

    /**
     * Restricted constructor.
     */
    protected Meta() {
    }

    @Override
    public BeanBuilder<? extends PositionHistoryResult> builder() {
      return new DirectBeanBuilder<PositionHistoryResult>(new PositionHistoryResult());
    }

    @Override
    public Class<? extends PositionHistoryResult> beanType() {
      return PositionHistoryResult.class;
    }

    @Override
    public Map<String, MetaProperty<?>> metaPropertyMap() {
      return _metaPropertyMap$;
    }

    //-----------------------------------------------------------------------
  }

  ///CLOVER:ON
  //-------------------------- AUTOGENERATED END --------------------------
}
