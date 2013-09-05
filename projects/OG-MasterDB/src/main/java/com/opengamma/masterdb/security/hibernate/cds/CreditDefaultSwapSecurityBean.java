/**
 * Copyright (C) 2009 - present by OpenGamma Inc. and the OpenGamma group of companies
 *
 * Please see distribution for license.
 */
package com.opengamma.masterdb.security.hibernate.cds;

import java.util.Map;

import org.joda.beans.BeanBuilder;
import org.joda.beans.BeanDefinition;
import org.joda.beans.JodaBeanUtils;
import org.joda.beans.MetaProperty;
import org.joda.beans.Property;
import org.joda.beans.PropertyDefinition;
import org.joda.beans.impl.direct.DirectMetaProperty;
import org.joda.beans.impl.direct.DirectMetaPropertyMap;

import com.opengamma.financial.security.cds.CreditDefaultSwapSecurity;
import com.opengamma.masterdb.security.hibernate.BusinessDayConventionBean;
import com.opengamma.masterdb.security.hibernate.DayCountBean;
import com.opengamma.masterdb.security.hibernate.DebtSeniorityBean;
import com.opengamma.masterdb.security.hibernate.ExternalIdBean;
import com.opengamma.masterdb.security.hibernate.FrequencyBean;
import com.opengamma.masterdb.security.hibernate.RestructuringClauseBean;
import com.opengamma.masterdb.security.hibernate.SecurityBean;
import com.opengamma.masterdb.security.hibernate.StubTypeBean;
import com.opengamma.masterdb.security.hibernate.ZonedDateTimeBean;
import com.opengamma.masterdb.security.hibernate.swap.NotionalBean;

/**
 * A Hibernate bean representation of {@link CreditDefaultSwapSecurity}.
 */
@BeanDefinition
public abstract class CreditDefaultSwapSecurityBean extends SecurityBean {
  
  @PropertyDefinition
  private Boolean _buy;
  @PropertyDefinition
  private ExternalIdBean _protectionBuyer;
  @PropertyDefinition
  private ExternalIdBean _protectionSeller;
  @PropertyDefinition
  private ExternalIdBean _referenceEntity;
  @PropertyDefinition
  private DebtSeniorityBean _debtSeniority;
  @PropertyDefinition
  private RestructuringClauseBean _restructuringClause;
  @PropertyDefinition
  private ExternalIdBean _regionId;
  @PropertyDefinition
  private ZonedDateTimeBean _startDate;
  @PropertyDefinition
  private ZonedDateTimeBean _effectiveDate;
  @PropertyDefinition
  private ZonedDateTimeBean _maturityDate;
  @PropertyDefinition
  private StubTypeBean _stubType;
  @PropertyDefinition
  private FrequencyBean _couponFrequency;
  @PropertyDefinition
  private DayCountBean _dayCount;
  @PropertyDefinition
  private BusinessDayConventionBean _businessDayConvention;
  @PropertyDefinition
  private Boolean _immAdjustMaturityDate;
  @PropertyDefinition
  private Boolean _adjustEffectiveDate;
  @PropertyDefinition
  private Boolean _adjustMaturityDate;
  @PropertyDefinition
  private NotionalBean _notional;
  @PropertyDefinition
  private Boolean _includeAccruedPremium;
  @PropertyDefinition
  private Boolean _protectionStart;
  
  public CreditDefaultSwapSecurityBean() {
    super();
  }
  
  //------------------------- AUTOGENERATED START -------------------------
  ///CLOVER:OFF
  /**
   * The meta-bean for {@code CreditDefaultSwapSecurityBean}.
   * @return the meta-bean, not null
   */
  public static CreditDefaultSwapSecurityBean.Meta meta() {
    return CreditDefaultSwapSecurityBean.Meta.INSTANCE;
  }

  static {
    JodaBeanUtils.registerMetaBean(CreditDefaultSwapSecurityBean.Meta.INSTANCE);
  }

  @Override
  public CreditDefaultSwapSecurityBean.Meta metaBean() {
    return CreditDefaultSwapSecurityBean.Meta.INSTANCE;
  }

  @Override
  protected Object propertyGet(String propertyName, boolean quiet) {
    switch (propertyName.hashCode()) {
      case 97926:  // buy
        return getBuy();
      case 2087835226:  // protectionBuyer
        return getProtectionBuyer();
      case 769920952:  // protectionSeller
        return getProtectionSeller();
      case 480652046:  // referenceEntity
        return getReferenceEntity();
      case 1737168171:  // debtSeniority
        return getDebtSeniority();
      case -1774904020:  // restructuringClause
        return getRestructuringClause();
      case -690339025:  // regionId
        return getRegionId();
      case -2129778896:  // startDate
        return getStartDate();
      case -930389515:  // effectiveDate
        return getEffectiveDate();
      case -414641441:  // maturityDate
        return getMaturityDate();
      case 1873675528:  // stubType
        return getStubType();
      case 144480214:  // couponFrequency
        return getCouponFrequency();
      case 1905311443:  // dayCount
        return getDayCount();
      case -1002835891:  // businessDayConvention
        return getBusinessDayConvention();
      case -1168632905:  // immAdjustMaturityDate
        return getImmAdjustMaturityDate();
      case -490317146:  // adjustEffectiveDate
        return getAdjustEffectiveDate();
      case -261898226:  // adjustMaturityDate
        return getAdjustMaturityDate();
      case 1585636160:  // notional
        return getNotional();
      case 2100149628:  // includeAccruedPremium
        return getIncludeAccruedPremium();
      case 2103482633:  // protectionStart
        return getProtectionStart();
    }
    return super.propertyGet(propertyName, quiet);
  }

  @Override
  protected void propertySet(String propertyName, Object newValue, boolean quiet) {
    switch (propertyName.hashCode()) {
      case 97926:  // buy
        setBuy((Boolean) newValue);
        return;
      case 2087835226:  // protectionBuyer
        setProtectionBuyer((ExternalIdBean) newValue);
        return;
      case 769920952:  // protectionSeller
        setProtectionSeller((ExternalIdBean) newValue);
        return;
      case 480652046:  // referenceEntity
        setReferenceEntity((ExternalIdBean) newValue);
        return;
      case 1737168171:  // debtSeniority
        setDebtSeniority((DebtSeniorityBean) newValue);
        return;
      case -1774904020:  // restructuringClause
        setRestructuringClause((RestructuringClauseBean) newValue);
        return;
      case -690339025:  // regionId
        setRegionId((ExternalIdBean) newValue);
        return;
      case -2129778896:  // startDate
        setStartDate((ZonedDateTimeBean) newValue);
        return;
      case -930389515:  // effectiveDate
        setEffectiveDate((ZonedDateTimeBean) newValue);
        return;
      case -414641441:  // maturityDate
        setMaturityDate((ZonedDateTimeBean) newValue);
        return;
      case 1873675528:  // stubType
        setStubType((StubTypeBean) newValue);
        return;
      case 144480214:  // couponFrequency
        setCouponFrequency((FrequencyBean) newValue);
        return;
      case 1905311443:  // dayCount
        setDayCount((DayCountBean) newValue);
        return;
      case -1002835891:  // businessDayConvention
        setBusinessDayConvention((BusinessDayConventionBean) newValue);
        return;
      case -1168632905:  // immAdjustMaturityDate
        setImmAdjustMaturityDate((Boolean) newValue);
        return;
      case -490317146:  // adjustEffectiveDate
        setAdjustEffectiveDate((Boolean) newValue);
        return;
      case -261898226:  // adjustMaturityDate
        setAdjustMaturityDate((Boolean) newValue);
        return;
      case 1585636160:  // notional
        setNotional((NotionalBean) newValue);
        return;
      case 2100149628:  // includeAccruedPremium
        setIncludeAccruedPremium((Boolean) newValue);
        return;
      case 2103482633:  // protectionStart
        setProtectionStart((Boolean) newValue);
        return;
    }
    super.propertySet(propertyName, newValue, quiet);
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (obj != null && obj.getClass() == this.getClass()) {
      CreditDefaultSwapSecurityBean other = (CreditDefaultSwapSecurityBean) obj;
      return JodaBeanUtils.equal(getBuy(), other.getBuy()) &&
          JodaBeanUtils.equal(getProtectionBuyer(), other.getProtectionBuyer()) &&
          JodaBeanUtils.equal(getProtectionSeller(), other.getProtectionSeller()) &&
          JodaBeanUtils.equal(getReferenceEntity(), other.getReferenceEntity()) &&
          JodaBeanUtils.equal(getDebtSeniority(), other.getDebtSeniority()) &&
          JodaBeanUtils.equal(getRestructuringClause(), other.getRestructuringClause()) &&
          JodaBeanUtils.equal(getRegionId(), other.getRegionId()) &&
          JodaBeanUtils.equal(getStartDate(), other.getStartDate()) &&
          JodaBeanUtils.equal(getEffectiveDate(), other.getEffectiveDate()) &&
          JodaBeanUtils.equal(getMaturityDate(), other.getMaturityDate()) &&
          JodaBeanUtils.equal(getStubType(), other.getStubType()) &&
          JodaBeanUtils.equal(getCouponFrequency(), other.getCouponFrequency()) &&
          JodaBeanUtils.equal(getDayCount(), other.getDayCount()) &&
          JodaBeanUtils.equal(getBusinessDayConvention(), other.getBusinessDayConvention()) &&
          JodaBeanUtils.equal(getImmAdjustMaturityDate(), other.getImmAdjustMaturityDate()) &&
          JodaBeanUtils.equal(getAdjustEffectiveDate(), other.getAdjustEffectiveDate()) &&
          JodaBeanUtils.equal(getAdjustMaturityDate(), other.getAdjustMaturityDate()) &&
          JodaBeanUtils.equal(getNotional(), other.getNotional()) &&
          JodaBeanUtils.equal(getIncludeAccruedPremium(), other.getIncludeAccruedPremium()) &&
          JodaBeanUtils.equal(getProtectionStart(), other.getProtectionStart()) &&
          super.equals(obj);
    }
    return false;
  }

  @Override
  public int hashCode() {
    int hash = 7;
    hash += hash * 31 + JodaBeanUtils.hashCode(getBuy());
    hash += hash * 31 + JodaBeanUtils.hashCode(getProtectionBuyer());
    hash += hash * 31 + JodaBeanUtils.hashCode(getProtectionSeller());
    hash += hash * 31 + JodaBeanUtils.hashCode(getReferenceEntity());
    hash += hash * 31 + JodaBeanUtils.hashCode(getDebtSeniority());
    hash += hash * 31 + JodaBeanUtils.hashCode(getRestructuringClause());
    hash += hash * 31 + JodaBeanUtils.hashCode(getRegionId());
    hash += hash * 31 + JodaBeanUtils.hashCode(getStartDate());
    hash += hash * 31 + JodaBeanUtils.hashCode(getEffectiveDate());
    hash += hash * 31 + JodaBeanUtils.hashCode(getMaturityDate());
    hash += hash * 31 + JodaBeanUtils.hashCode(getStubType());
    hash += hash * 31 + JodaBeanUtils.hashCode(getCouponFrequency());
    hash += hash * 31 + JodaBeanUtils.hashCode(getDayCount());
    hash += hash * 31 + JodaBeanUtils.hashCode(getBusinessDayConvention());
    hash += hash * 31 + JodaBeanUtils.hashCode(getImmAdjustMaturityDate());
    hash += hash * 31 + JodaBeanUtils.hashCode(getAdjustEffectiveDate());
    hash += hash * 31 + JodaBeanUtils.hashCode(getAdjustMaturityDate());
    hash += hash * 31 + JodaBeanUtils.hashCode(getNotional());
    hash += hash * 31 + JodaBeanUtils.hashCode(getIncludeAccruedPremium());
    hash += hash * 31 + JodaBeanUtils.hashCode(getProtectionStart());
    return hash ^ super.hashCode();
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the buy.
   * @return the value of the property
   */
  public Boolean getBuy() {
    return _buy;
  }

  /**
   * Sets the buy.
   * @param buy  the new value of the property
   */
  public void setBuy(Boolean buy) {
    this._buy = buy;
  }

  /**
   * Gets the the {@code buy} property.
   * @return the property, not null
   */
  public final Property<Boolean> buy() {
    return metaBean().buy().createProperty(this);
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the protectionBuyer.
   * @return the value of the property
   */
  public ExternalIdBean getProtectionBuyer() {
    return _protectionBuyer;
  }

  /**
   * Sets the protectionBuyer.
   * @param protectionBuyer  the new value of the property
   */
  public void setProtectionBuyer(ExternalIdBean protectionBuyer) {
    this._protectionBuyer = protectionBuyer;
  }

  /**
   * Gets the the {@code protectionBuyer} property.
   * @return the property, not null
   */
  public final Property<ExternalIdBean> protectionBuyer() {
    return metaBean().protectionBuyer().createProperty(this);
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the protectionSeller.
   * @return the value of the property
   */
  public ExternalIdBean getProtectionSeller() {
    return _protectionSeller;
  }

  /**
   * Sets the protectionSeller.
   * @param protectionSeller  the new value of the property
   */
  public void setProtectionSeller(ExternalIdBean protectionSeller) {
    this._protectionSeller = protectionSeller;
  }

  /**
   * Gets the the {@code protectionSeller} property.
   * @return the property, not null
   */
  public final Property<ExternalIdBean> protectionSeller() {
    return metaBean().protectionSeller().createProperty(this);
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the referenceEntity.
   * @return the value of the property
   */
  public ExternalIdBean getReferenceEntity() {
    return _referenceEntity;
  }

  /**
   * Sets the referenceEntity.
   * @param referenceEntity  the new value of the property
   */
  public void setReferenceEntity(ExternalIdBean referenceEntity) {
    this._referenceEntity = referenceEntity;
  }

  /**
   * Gets the the {@code referenceEntity} property.
   * @return the property, not null
   */
  public final Property<ExternalIdBean> referenceEntity() {
    return metaBean().referenceEntity().createProperty(this);
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the debtSeniority.
   * @return the value of the property
   */
  public DebtSeniorityBean getDebtSeniority() {
    return _debtSeniority;
  }

  /**
   * Sets the debtSeniority.
   * @param debtSeniority  the new value of the property
   */
  public void setDebtSeniority(DebtSeniorityBean debtSeniority) {
    this._debtSeniority = debtSeniority;
  }

  /**
   * Gets the the {@code debtSeniority} property.
   * @return the property, not null
   */
  public final Property<DebtSeniorityBean> debtSeniority() {
    return metaBean().debtSeniority().createProperty(this);
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the restructuringClause.
   * @return the value of the property
   */
  public RestructuringClauseBean getRestructuringClause() {
    return _restructuringClause;
  }

  /**
   * Sets the restructuringClause.
   * @param restructuringClause  the new value of the property
   */
  public void setRestructuringClause(RestructuringClauseBean restructuringClause) {
    this._restructuringClause = restructuringClause;
  }

  /**
   * Gets the the {@code restructuringClause} property.
   * @return the property, not null
   */
  public final Property<RestructuringClauseBean> restructuringClause() {
    return metaBean().restructuringClause().createProperty(this);
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the regionId.
   * @return the value of the property
   */
  public ExternalIdBean getRegionId() {
    return _regionId;
  }

  /**
   * Sets the regionId.
   * @param regionId  the new value of the property
   */
  public void setRegionId(ExternalIdBean regionId) {
    this._regionId = regionId;
  }

  /**
   * Gets the the {@code regionId} property.
   * @return the property, not null
   */
  public final Property<ExternalIdBean> regionId() {
    return metaBean().regionId().createProperty(this);
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the startDate.
   * @return the value of the property
   */
  public ZonedDateTimeBean getStartDate() {
    return _startDate;
  }

  /**
   * Sets the startDate.
   * @param startDate  the new value of the property
   */
  public void setStartDate(ZonedDateTimeBean startDate) {
    this._startDate = startDate;
  }

  /**
   * Gets the the {@code startDate} property.
   * @return the property, not null
   */
  public final Property<ZonedDateTimeBean> startDate() {
    return metaBean().startDate().createProperty(this);
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the effectiveDate.
   * @return the value of the property
   */
  public ZonedDateTimeBean getEffectiveDate() {
    return _effectiveDate;
  }

  /**
   * Sets the effectiveDate.
   * @param effectiveDate  the new value of the property
   */
  public void setEffectiveDate(ZonedDateTimeBean effectiveDate) {
    this._effectiveDate = effectiveDate;
  }

  /**
   * Gets the the {@code effectiveDate} property.
   * @return the property, not null
   */
  public final Property<ZonedDateTimeBean> effectiveDate() {
    return metaBean().effectiveDate().createProperty(this);
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the maturityDate.
   * @return the value of the property
   */
  public ZonedDateTimeBean getMaturityDate() {
    return _maturityDate;
  }

  /**
   * Sets the maturityDate.
   * @param maturityDate  the new value of the property
   */
  public void setMaturityDate(ZonedDateTimeBean maturityDate) {
    this._maturityDate = maturityDate;
  }

  /**
   * Gets the the {@code maturityDate} property.
   * @return the property, not null
   */
  public final Property<ZonedDateTimeBean> maturityDate() {
    return metaBean().maturityDate().createProperty(this);
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the stubType.
   * @return the value of the property
   */
  public StubTypeBean getStubType() {
    return _stubType;
  }

  /**
   * Sets the stubType.
   * @param stubType  the new value of the property
   */
  public void setStubType(StubTypeBean stubType) {
    this._stubType = stubType;
  }

  /**
   * Gets the the {@code stubType} property.
   * @return the property, not null
   */
  public final Property<StubTypeBean> stubType() {
    return metaBean().stubType().createProperty(this);
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the couponFrequency.
   * @return the value of the property
   */
  public FrequencyBean getCouponFrequency() {
    return _couponFrequency;
  }

  /**
   * Sets the couponFrequency.
   * @param couponFrequency  the new value of the property
   */
  public void setCouponFrequency(FrequencyBean couponFrequency) {
    this._couponFrequency = couponFrequency;
  }

  /**
   * Gets the the {@code couponFrequency} property.
   * @return the property, not null
   */
  public final Property<FrequencyBean> couponFrequency() {
    return metaBean().couponFrequency().createProperty(this);
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the dayCount.
   * @return the value of the property
   */
  public DayCountBean getDayCount() {
    return _dayCount;
  }

  /**
   * Sets the dayCount.
   * @param dayCount  the new value of the property
   */
  public void setDayCount(DayCountBean dayCount) {
    this._dayCount = dayCount;
  }

  /**
   * Gets the the {@code dayCount} property.
   * @return the property, not null
   */
  public final Property<DayCountBean> dayCount() {
    return metaBean().dayCount().createProperty(this);
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the businessDayConvention.
   * @return the value of the property
   */
  public BusinessDayConventionBean getBusinessDayConvention() {
    return _businessDayConvention;
  }

  /**
   * Sets the businessDayConvention.
   * @param businessDayConvention  the new value of the property
   */
  public void setBusinessDayConvention(BusinessDayConventionBean businessDayConvention) {
    this._businessDayConvention = businessDayConvention;
  }

  /**
   * Gets the the {@code businessDayConvention} property.
   * @return the property, not null
   */
  public final Property<BusinessDayConventionBean> businessDayConvention() {
    return metaBean().businessDayConvention().createProperty(this);
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the immAdjustMaturityDate.
   * @return the value of the property
   */
  public Boolean getImmAdjustMaturityDate() {
    return _immAdjustMaturityDate;
  }

  /**
   * Sets the immAdjustMaturityDate.
   * @param immAdjustMaturityDate  the new value of the property
   */
  public void setImmAdjustMaturityDate(Boolean immAdjustMaturityDate) {
    this._immAdjustMaturityDate = immAdjustMaturityDate;
  }

  /**
   * Gets the the {@code immAdjustMaturityDate} property.
   * @return the property, not null
   */
  public final Property<Boolean> immAdjustMaturityDate() {
    return metaBean().immAdjustMaturityDate().createProperty(this);
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the adjustEffectiveDate.
   * @return the value of the property
   */
  public Boolean getAdjustEffectiveDate() {
    return _adjustEffectiveDate;
  }

  /**
   * Sets the adjustEffectiveDate.
   * @param adjustEffectiveDate  the new value of the property
   */
  public void setAdjustEffectiveDate(Boolean adjustEffectiveDate) {
    this._adjustEffectiveDate = adjustEffectiveDate;
  }

  /**
   * Gets the the {@code adjustEffectiveDate} property.
   * @return the property, not null
   */
  public final Property<Boolean> adjustEffectiveDate() {
    return metaBean().adjustEffectiveDate().createProperty(this);
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the adjustMaturityDate.
   * @return the value of the property
   */
  public Boolean getAdjustMaturityDate() {
    return _adjustMaturityDate;
  }

  /**
   * Sets the adjustMaturityDate.
   * @param adjustMaturityDate  the new value of the property
   */
  public void setAdjustMaturityDate(Boolean adjustMaturityDate) {
    this._adjustMaturityDate = adjustMaturityDate;
  }

  /**
   * Gets the the {@code adjustMaturityDate} property.
   * @return the property, not null
   */
  public final Property<Boolean> adjustMaturityDate() {
    return metaBean().adjustMaturityDate().createProperty(this);
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the notional.
   * @return the value of the property
   */
  public NotionalBean getNotional() {
    return _notional;
  }

  /**
   * Sets the notional.
   * @param notional  the new value of the property
   */
  public void setNotional(NotionalBean notional) {
    this._notional = notional;
  }

  /**
   * Gets the the {@code notional} property.
   * @return the property, not null
   */
  public final Property<NotionalBean> notional() {
    return metaBean().notional().createProperty(this);
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the includeAccruedPremium.
   * @return the value of the property
   */
  public Boolean getIncludeAccruedPremium() {
    return _includeAccruedPremium;
  }

  /**
   * Sets the includeAccruedPremium.
   * @param includeAccruedPremium  the new value of the property
   */
  public void setIncludeAccruedPremium(Boolean includeAccruedPremium) {
    this._includeAccruedPremium = includeAccruedPremium;
  }

  /**
   * Gets the the {@code includeAccruedPremium} property.
   * @return the property, not null
   */
  public final Property<Boolean> includeAccruedPremium() {
    return metaBean().includeAccruedPremium().createProperty(this);
  }

  //-----------------------------------------------------------------------
  /**
   * Gets the protectionStart.
   * @return the value of the property
   */
  public Boolean getProtectionStart() {
    return _protectionStart;
  }

  /**
   * Sets the protectionStart.
   * @param protectionStart  the new value of the property
   */
  public void setProtectionStart(Boolean protectionStart) {
    this._protectionStart = protectionStart;
  }

  /**
   * Gets the the {@code protectionStart} property.
   * @return the property, not null
   */
  public final Property<Boolean> protectionStart() {
    return metaBean().protectionStart().createProperty(this);
  }

  //-----------------------------------------------------------------------
  /**
   * The meta-bean for {@code CreditDefaultSwapSecurityBean}.
   */
  public static class Meta extends SecurityBean.Meta {
    /**
     * The singleton instance of the meta-bean.
     */
    static final Meta INSTANCE = new Meta();

    /**
     * The meta-property for the {@code buy} property.
     */
    private final MetaProperty<Boolean> _buy = DirectMetaProperty.ofReadWrite(
        this, "buy", CreditDefaultSwapSecurityBean.class, Boolean.class);
    /**
     * The meta-property for the {@code protectionBuyer} property.
     */
    private final MetaProperty<ExternalIdBean> _protectionBuyer = DirectMetaProperty.ofReadWrite(
        this, "protectionBuyer", CreditDefaultSwapSecurityBean.class, ExternalIdBean.class);
    /**
     * The meta-property for the {@code protectionSeller} property.
     */
    private final MetaProperty<ExternalIdBean> _protectionSeller = DirectMetaProperty.ofReadWrite(
        this, "protectionSeller", CreditDefaultSwapSecurityBean.class, ExternalIdBean.class);
    /**
     * The meta-property for the {@code referenceEntity} property.
     */
    private final MetaProperty<ExternalIdBean> _referenceEntity = DirectMetaProperty.ofReadWrite(
        this, "referenceEntity", CreditDefaultSwapSecurityBean.class, ExternalIdBean.class);
    /**
     * The meta-property for the {@code debtSeniority} property.
     */
    private final MetaProperty<DebtSeniorityBean> _debtSeniority = DirectMetaProperty.ofReadWrite(
        this, "debtSeniority", CreditDefaultSwapSecurityBean.class, DebtSeniorityBean.class);
    /**
     * The meta-property for the {@code restructuringClause} property.
     */
    private final MetaProperty<RestructuringClauseBean> _restructuringClause = DirectMetaProperty.ofReadWrite(
        this, "restructuringClause", CreditDefaultSwapSecurityBean.class, RestructuringClauseBean.class);
    /**
     * The meta-property for the {@code regionId} property.
     */
    private final MetaProperty<ExternalIdBean> _regionId = DirectMetaProperty.ofReadWrite(
        this, "regionId", CreditDefaultSwapSecurityBean.class, ExternalIdBean.class);
    /**
     * The meta-property for the {@code startDate} property.
     */
    private final MetaProperty<ZonedDateTimeBean> _startDate = DirectMetaProperty.ofReadWrite(
        this, "startDate", CreditDefaultSwapSecurityBean.class, ZonedDateTimeBean.class);
    /**
     * The meta-property for the {@code effectiveDate} property.
     */
    private final MetaProperty<ZonedDateTimeBean> _effectiveDate = DirectMetaProperty.ofReadWrite(
        this, "effectiveDate", CreditDefaultSwapSecurityBean.class, ZonedDateTimeBean.class);
    /**
     * The meta-property for the {@code maturityDate} property.
     */
    private final MetaProperty<ZonedDateTimeBean> _maturityDate = DirectMetaProperty.ofReadWrite(
        this, "maturityDate", CreditDefaultSwapSecurityBean.class, ZonedDateTimeBean.class);
    /**
     * The meta-property for the {@code stubType} property.
     */
    private final MetaProperty<StubTypeBean> _stubType = DirectMetaProperty.ofReadWrite(
        this, "stubType", CreditDefaultSwapSecurityBean.class, StubTypeBean.class);
    /**
     * The meta-property for the {@code couponFrequency} property.
     */
    private final MetaProperty<FrequencyBean> _couponFrequency = DirectMetaProperty.ofReadWrite(
        this, "couponFrequency", CreditDefaultSwapSecurityBean.class, FrequencyBean.class);
    /**
     * The meta-property for the {@code dayCount} property.
     */
    private final MetaProperty<DayCountBean> _dayCount = DirectMetaProperty.ofReadWrite(
        this, "dayCount", CreditDefaultSwapSecurityBean.class, DayCountBean.class);
    /**
     * The meta-property for the {@code businessDayConvention} property.
     */
    private final MetaProperty<BusinessDayConventionBean> _businessDayConvention = DirectMetaProperty.ofReadWrite(
        this, "businessDayConvention", CreditDefaultSwapSecurityBean.class, BusinessDayConventionBean.class);
    /**
     * The meta-property for the {@code immAdjustMaturityDate} property.
     */
    private final MetaProperty<Boolean> _immAdjustMaturityDate = DirectMetaProperty.ofReadWrite(
        this, "immAdjustMaturityDate", CreditDefaultSwapSecurityBean.class, Boolean.class);
    /**
     * The meta-property for the {@code adjustEffectiveDate} property.
     */
    private final MetaProperty<Boolean> _adjustEffectiveDate = DirectMetaProperty.ofReadWrite(
        this, "adjustEffectiveDate", CreditDefaultSwapSecurityBean.class, Boolean.class);
    /**
     * The meta-property for the {@code adjustMaturityDate} property.
     */
    private final MetaProperty<Boolean> _adjustMaturityDate = DirectMetaProperty.ofReadWrite(
        this, "adjustMaturityDate", CreditDefaultSwapSecurityBean.class, Boolean.class);
    /**
     * The meta-property for the {@code notional} property.
     */
    private final MetaProperty<NotionalBean> _notional = DirectMetaProperty.ofReadWrite(
        this, "notional", CreditDefaultSwapSecurityBean.class, NotionalBean.class);
    /**
     * The meta-property for the {@code includeAccruedPremium} property.
     */
    private final MetaProperty<Boolean> _includeAccruedPremium = DirectMetaProperty.ofReadWrite(
        this, "includeAccruedPremium", CreditDefaultSwapSecurityBean.class, Boolean.class);
    /**
     * The meta-property for the {@code protectionStart} property.
     */
    private final MetaProperty<Boolean> _protectionStart = DirectMetaProperty.ofReadWrite(
        this, "protectionStart", CreditDefaultSwapSecurityBean.class, Boolean.class);
    /**
     * The meta-properties.
     */
    private final Map<String, MetaProperty<?>> _metaPropertyMap$ = new DirectMetaPropertyMap(
        this, (DirectMetaPropertyMap) super.metaPropertyMap(),
        "buy",
        "protectionBuyer",
        "protectionSeller",
        "referenceEntity",
        "debtSeniority",
        "restructuringClause",
        "regionId",
        "startDate",
        "effectiveDate",
        "maturityDate",
        "stubType",
        "couponFrequency",
        "dayCount",
        "businessDayConvention",
        "immAdjustMaturityDate",
        "adjustEffectiveDate",
        "adjustMaturityDate",
        "notional",
        "includeAccruedPremium",
        "protectionStart");

    /**
     * Restricted constructor.
     */
    protected Meta() {
    }

    @Override
    protected MetaProperty<?> metaPropertyGet(String propertyName) {
      switch (propertyName.hashCode()) {
        case 97926:  // buy
          return _buy;
        case 2087835226:  // protectionBuyer
          return _protectionBuyer;
        case 769920952:  // protectionSeller
          return _protectionSeller;
        case 480652046:  // referenceEntity
          return _referenceEntity;
        case 1737168171:  // debtSeniority
          return _debtSeniority;
        case -1774904020:  // restructuringClause
          return _restructuringClause;
        case -690339025:  // regionId
          return _regionId;
        case -2129778896:  // startDate
          return _startDate;
        case -930389515:  // effectiveDate
          return _effectiveDate;
        case -414641441:  // maturityDate
          return _maturityDate;
        case 1873675528:  // stubType
          return _stubType;
        case 144480214:  // couponFrequency
          return _couponFrequency;
        case 1905311443:  // dayCount
          return _dayCount;
        case -1002835891:  // businessDayConvention
          return _businessDayConvention;
        case -1168632905:  // immAdjustMaturityDate
          return _immAdjustMaturityDate;
        case -490317146:  // adjustEffectiveDate
          return _adjustEffectiveDate;
        case -261898226:  // adjustMaturityDate
          return _adjustMaturityDate;
        case 1585636160:  // notional
          return _notional;
        case 2100149628:  // includeAccruedPremium
          return _includeAccruedPremium;
        case 2103482633:  // protectionStart
          return _protectionStart;
      }
      return super.metaPropertyGet(propertyName);
    }

    @Override
    public BeanBuilder<? extends CreditDefaultSwapSecurityBean> builder() {
      throw new UnsupportedOperationException("CreditDefaultSwapSecurityBean is an abstract class");
    }

    @Override
    public Class<? extends CreditDefaultSwapSecurityBean> beanType() {
      return CreditDefaultSwapSecurityBean.class;
    }

    @Override
    public Map<String, MetaProperty<?>> metaPropertyMap() {
      return _metaPropertyMap$;
    }

    //-----------------------------------------------------------------------
    /**
     * The meta-property for the {@code buy} property.
     * @return the meta-property, not null
     */
    public final MetaProperty<Boolean> buy() {
      return _buy;
    }

    /**
     * The meta-property for the {@code protectionBuyer} property.
     * @return the meta-property, not null
     */
    public final MetaProperty<ExternalIdBean> protectionBuyer() {
      return _protectionBuyer;
    }

    /**
     * The meta-property for the {@code protectionSeller} property.
     * @return the meta-property, not null
     */
    public final MetaProperty<ExternalIdBean> protectionSeller() {
      return _protectionSeller;
    }

    /**
     * The meta-property for the {@code referenceEntity} property.
     * @return the meta-property, not null
     */
    public final MetaProperty<ExternalIdBean> referenceEntity() {
      return _referenceEntity;
    }

    /**
     * The meta-property for the {@code debtSeniority} property.
     * @return the meta-property, not null
     */
    public final MetaProperty<DebtSeniorityBean> debtSeniority() {
      return _debtSeniority;
    }

    /**
     * The meta-property for the {@code restructuringClause} property.
     * @return the meta-property, not null
     */
    public final MetaProperty<RestructuringClauseBean> restructuringClause() {
      return _restructuringClause;
    }

    /**
     * The meta-property for the {@code regionId} property.
     * @return the meta-property, not null
     */
    public final MetaProperty<ExternalIdBean> regionId() {
      return _regionId;
    }

    /**
     * The meta-property for the {@code startDate} property.
     * @return the meta-property, not null
     */
    public final MetaProperty<ZonedDateTimeBean> startDate() {
      return _startDate;
    }

    /**
     * The meta-property for the {@code effectiveDate} property.
     * @return the meta-property, not null
     */
    public final MetaProperty<ZonedDateTimeBean> effectiveDate() {
      return _effectiveDate;
    }

    /**
     * The meta-property for the {@code maturityDate} property.
     * @return the meta-property, not null
     */
    public final MetaProperty<ZonedDateTimeBean> maturityDate() {
      return _maturityDate;
    }

    /**
     * The meta-property for the {@code stubType} property.
     * @return the meta-property, not null
     */
    public final MetaProperty<StubTypeBean> stubType() {
      return _stubType;
    }

    /**
     * The meta-property for the {@code couponFrequency} property.
     * @return the meta-property, not null
     */
    public final MetaProperty<FrequencyBean> couponFrequency() {
      return _couponFrequency;
    }

    /**
     * The meta-property for the {@code dayCount} property.
     * @return the meta-property, not null
     */
    public final MetaProperty<DayCountBean> dayCount() {
      return _dayCount;
    }

    /**
     * The meta-property for the {@code businessDayConvention} property.
     * @return the meta-property, not null
     */
    public final MetaProperty<BusinessDayConventionBean> businessDayConvention() {
      return _businessDayConvention;
    }

    /**
     * The meta-property for the {@code immAdjustMaturityDate} property.
     * @return the meta-property, not null
     */
    public final MetaProperty<Boolean> immAdjustMaturityDate() {
      return _immAdjustMaturityDate;
    }

    /**
     * The meta-property for the {@code adjustEffectiveDate} property.
     * @return the meta-property, not null
     */
    public final MetaProperty<Boolean> adjustEffectiveDate() {
      return _adjustEffectiveDate;
    }

    /**
     * The meta-property for the {@code adjustMaturityDate} property.
     * @return the meta-property, not null
     */
    public final MetaProperty<Boolean> adjustMaturityDate() {
      return _adjustMaturityDate;
    }

    /**
     * The meta-property for the {@code notional} property.
     * @return the meta-property, not null
     */
    public final MetaProperty<NotionalBean> notional() {
      return _notional;
    }

    /**
     * The meta-property for the {@code includeAccruedPremium} property.
     * @return the meta-property, not null
     */
    public final MetaProperty<Boolean> includeAccruedPremium() {
      return _includeAccruedPremium;
    }

    /**
     * The meta-property for the {@code protectionStart} property.
     * @return the meta-property, not null
     */
    public final MetaProperty<Boolean> protectionStart() {
      return _protectionStart;
    }

  }

  ///CLOVER:ON
  //-------------------------- AUTOGENERATED END --------------------------
}
