/**
 * Copyright (C) 2013 - present by OpenGamma Inc. and the OpenGamma group of companies
 * 
 * Please see distribution for license.
 */
package com.opengamma.financial.analytics.model.credit.isda.cds;

import static com.opengamma.financial.analytics.model.credit.CreditInstrumentPropertyNamesAndValues.PROPERTY_SPREAD_CURVE_SHIFT;
import static com.opengamma.financial.analytics.model.credit.CreditInstrumentPropertyNamesAndValues.PROPERTY_SPREAD_CURVE_SHIFT_TYPE;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.threeten.bp.ZonedDateTime;

import com.google.common.collect.Iterables;
import com.google.common.collect.Sets;
import com.opengamma.OpenGammaRuntimeException;
import com.opengamma.analytics.financial.credit.creditdefaultswap.StandardCDSCoupon;
import com.opengamma.analytics.financial.credit.creditdefaultswap.definition.legacy.LegacyCreditDefaultSwapDefinition;
import com.opengamma.analytics.financial.credit.creditdefaultswap.definition.legacy.LegacyVanillaCreditDefaultSwapDefinition;
import com.opengamma.analytics.financial.credit.creditdefaultswap.definition.standard.StandardCreditDefaultSwapDefinition;
import com.opengamma.analytics.financial.credit.creditdefaultswap.definition.vanilla.CreditDefaultSwapDefinition;
import com.opengamma.analytics.financial.credit.creditdefaultswap.pricing.vanilla.isdanew.CDSAnalytic;
import com.opengamma.analytics.financial.credit.creditdefaultswap.pricing.vanilla.isdanew.CDSAnalyticFactory;
import com.opengamma.analytics.financial.credit.creditdefaultswap.pricing.vanilla.isdanew.ISDACompliantCreditCurve;
import com.opengamma.analytics.financial.credit.creditdefaultswap.pricing.vanilla.isdanew.ISDACompliantYieldCurve;
import com.opengamma.analytics.math.curve.NodalObjectsCurve;
import com.opengamma.core.holiday.HolidaySource;
import com.opengamma.core.organization.OrganizationSource;
import com.opengamma.core.region.RegionSource;
import com.opengamma.core.security.SecuritySource;
import com.opengamma.core.value.MarketDataRequirementNames;
import com.opengamma.engine.ComputationTarget;
import com.opengamma.engine.ComputationTargetSpecification;
import com.opengamma.engine.function.AbstractFunction;
import com.opengamma.engine.function.FunctionCompilationContext;
import com.opengamma.engine.function.FunctionExecutionContext;
import com.opengamma.engine.function.FunctionInputs;
import com.opengamma.engine.target.ComputationTargetType;
import com.opengamma.engine.value.ComputedValue;
import com.opengamma.engine.value.ValueProperties;
import com.opengamma.engine.value.ValuePropertyNames;
import com.opengamma.engine.value.ValueRequirement;
import com.opengamma.engine.value.ValueRequirementNames;
import com.opengamma.engine.value.ValueSpecification;
import com.opengamma.financial.OpenGammaCompilationContext;
import com.opengamma.financial.OpenGammaExecutionContext;
import com.opengamma.financial.analytics.conversion.CreditDefaultSwapSecurityConverter;
import com.opengamma.financial.analytics.model.YieldCurveFunctionUtils;
import com.opengamma.financial.analytics.model.credit.CreditFunctionUtils;
import com.opengamma.financial.analytics.model.credit.CreditInstrumentPropertyNamesAndValues;
import com.opengamma.financial.analytics.model.credit.CreditSecurityToIdentifierVisitor;
import com.opengamma.financial.analytics.model.credit.CreditSecurityToRecoveryRateVisitor;
import com.opengamma.financial.analytics.model.credit.IMMDateGenerator;
import com.opengamma.financial.convention.HolidaySourceCalendarAdapter;
import com.opengamma.financial.convention.businessday.BusinessDayConvention;
import com.opengamma.financial.convention.businessday.BusinessDayConventionFactory;
import com.opengamma.financial.convention.calendar.Calendar;
import com.opengamma.financial.credit.CdsRecoveryRateIdentifier;
import com.opengamma.financial.security.FinancialSecurity;
import com.opengamma.financial.security.FinancialSecurityTypes;
import com.opengamma.financial.security.FinancialSecurityUtils;
import com.opengamma.financial.security.cds.CreditDefaultSwapSecurity;
import com.opengamma.util.ArgumentChecker;
import com.opengamma.util.ParallelArrayBinarySort;
import com.opengamma.util.async.AsynchronousExecution;
import com.opengamma.util.time.Tenor;

/**
 * 
 */
//TODO rename to make clear that these functions use the ISDA methodology (specifically, for effective dates)
public abstract class StandardVanillaCDSFunction extends AbstractFunction.NonCompiledInvoker {
  private static final BusinessDayConvention FOLLOWING = BusinessDayConventionFactory.INSTANCE.getBusinessDayConvention("Following");
  private final String[] _valueRequirements;
  private static final Logger s_logger = LoggerFactory.getLogger(StandardVanillaCDSFunction.class);

  public StandardVanillaCDSFunction(final String... valueRequirements) {
    ArgumentChecker.notNull(valueRequirements, "value requirements");
    _valueRequirements = valueRequirements;
  }

  @Override
  public Set<ComputedValue> execute(final FunctionExecutionContext executionContext, final FunctionInputs inputs, final ComputationTarget target,
      final Set<ValueRequirement> desiredValues) throws AsynchronousExecution {
    final HolidaySource holidaySource = OpenGammaExecutionContext.getHolidaySource(executionContext);
    final SecuritySource securitySource = OpenGammaExecutionContext.getSecuritySource(executionContext);
    final RegionSource regionSource = OpenGammaExecutionContext.getRegionSource(executionContext);
    OrganizationSource organizationSource = OpenGammaExecutionContext.getOrganizationSource(executionContext);
    final CreditDefaultSwapSecurityConverter converter = new CreditDefaultSwapSecurityConverter(holidaySource, regionSource, organizationSource);
    final ZonedDateTime valuationTime = ZonedDateTime.now(executionContext.getValuationClock());
    final CreditDefaultSwapSecurity security = (CreditDefaultSwapSecurity) target.getSecurity();
    final Calendar calendar = new HolidaySourceCalendarAdapter(holidaySource, FinancialSecurityUtils.getCurrency(security));
    final CdsRecoveryRateIdentifier recoveryRateIdentifier = security.accept(new CreditSecurityToRecoveryRateVisitor(securitySource));
    Object recoveryRateObject = inputs.getValue(new ValueRequirement(MarketDataRequirementNames.MARKET_VALUE, ComputationTargetType.PRIMITIVE, recoveryRateIdentifier.getExternalId()));
    if (recoveryRateObject == null) {
      throw new OpenGammaRuntimeException("Could not get recovery rate");
      //s_logger.warn("Could not get recovery rate, defaulting to 0.4: " + recoveryRateIdentifier);
      //recoveryRateObject = 0.4;
    }
    final double recoveryRate = (Double) recoveryRateObject;
    LegacyVanillaCreditDefaultSwapDefinition definition = (LegacyVanillaCreditDefaultSwapDefinition) security.accept(converter);
    definition = definition.withEffectiveDate(FOLLOWING.adjustDate(calendar, valuationTime.withHour(0).withMinute(0).withSecond(0).withNano(0).plusDays(1)));
    definition = definition.withRecoveryRate(recoveryRate);
    final Object yieldCurveObject = inputs.getValue(ValueRequirementNames.YIELD_CURVE);
    if (yieldCurveObject == null) {
      throw new OpenGammaRuntimeException("Could not get yield curve");
    }
    final Object spreadCurveObject = inputs.getValue(ValueRequirementNames.CREDIT_SPREAD_CURVE);
    if (spreadCurveObject == null) {
      throw new OpenGammaRuntimeException("Could not get credit spread curve");
    }
    final ISDACompliantYieldCurve yieldCurve = (ISDACompliantYieldCurve) yieldCurveObject;
    final NodalObjectsCurve<?, ?> spreadCurve = (NodalObjectsCurve<?, ?>) spreadCurveObject;
    final Tenor[] tenors = CreditFunctionUtils.getTenors(spreadCurve.getXData());
    final Double[] marketSpreadObjects = CreditFunctionUtils.getSpreads(spreadCurve.getYData());
    ParallelArrayBinarySort.parallelBinarySort(tenors, marketSpreadObjects);
    final int n = tenors.length;
    final ZonedDateTime[] times = new ZonedDateTime[n];
    final double[] marketSpreads = new double[n];
    for (int i = 0; i < n; i++) {
      times[i] = IMMDateGenerator.getNextIMMDate(valuationTime, tenors[i]).withHour(0).withMinute(0).withSecond(0).withNano(0);
      marketSpreads[i] = marketSpreadObjects[i] * 1e-4;
    }
    ISDACompliantCreditCurve hazardCurve = (ISDACompliantCreditCurve) inputs.getValue(ValueRequirementNames.HAZARD_RATE_CURVE);
    final CDSAnalyticFactory analyticFactory = new CDSAnalyticFactory(0, definition.getCouponFrequency().getPeriod())
        .with(definition.getBusinessDayAdjustmentConvention())
        .with(definition.getCalendar()).with(definition.getStubType())
        .withAccualDCC(definition.getDayCountFractionConvention());
    final CDSAnalytic pricingCDS = analyticFactory.makeCDS(definition.getStartDate().toLocalDate(), definition.getEffectiveDate().toLocalDate(), definition.getMaturityDate().toLocalDate());
    final ValueProperties properties = desiredValues.iterator().next().getConstraints().copy()
        .with(ValuePropertyNames.FUNCTION, getUniqueId())
        .get();
    return getComputedValue(definition, yieldCurve, times, marketSpreads, valuationTime, target, properties, inputs, hazardCurve, pricingCDS);
  }

  @Override
  public ComputationTargetType getTargetType() {
    return FinancialSecurityTypes.STANDARD_VANILLA_CDS_SECURITY.or(FinancialSecurityTypes.LEGACY_VANILLA_CDS_SECURITY);
  }

  @Override
  public Set<ValueSpecification> getResults(final FunctionCompilationContext context, final ComputationTarget target) {
    final ValueProperties properties = ValueProperties.all();
    final Set<ValueSpecification> results = new HashSet<>();
    for (final String valueRequirement : _valueRequirements) {
      results.add(new ValueSpecification(valueRequirement, target.toSpecification(), properties));
    }
    return results;
  }

  @Override
  public Set<ValueRequirement> getRequirements(final FunctionCompilationContext context, final ComputationTarget target, final ValueRequirement desiredValue) {
    final ValueProperties constraints = desiredValue.getConstraints();
    //TODO add check for calculation method = ISDA
    final Set<String> yieldCurveNames = constraints.getValues(CreditInstrumentPropertyNamesAndValues.PROPERTY_YIELD_CURVE);
    if (yieldCurveNames == null || yieldCurveNames.size() != 1) {
      return null;
    }
    final Set<String> yieldCurveCalculationConfigNames = constraints.getValues(CreditInstrumentPropertyNamesAndValues.PROPERTY_YIELD_CURVE_CALCULATION_CONFIG);
    if (yieldCurveCalculationConfigNames == null || yieldCurveCalculationConfigNames.size() != 1) {
      return null;
    }
    final Set<String> yieldCurveCalculationMethodNames = constraints.getValues(CreditInstrumentPropertyNamesAndValues.PROPERTY_YIELD_CURVE_CALCULATION_METHOD);
    if (yieldCurveCalculationMethodNames == null || yieldCurveCalculationMethodNames.size() != 1) {
      return null;
    }
    final SecuritySource securitySource = OpenGammaCompilationContext.getSecuritySource(context);
    final CreditSecurityToIdentifierVisitor identifierVisitor = new CreditSecurityToIdentifierVisitor(securitySource);
    final FinancialSecurity security = (FinancialSecurity) target.getSecurity();
    final String spreadCurveName = security.accept(identifierVisitor).getUniqueId().getValue();
    final CdsRecoveryRateIdentifier recoveryRateIdentifier = security.accept(new CreditSecurityToRecoveryRateVisitor(securitySource));
    //    final Set<String> spreadCurveNames = constraints.getValues(CreditInstrumentPropertyNamesAndValues.PROPERTY_SPREAD_CURVE);
    //    if (spreadCurveNames == null || spreadCurveNames.size() != 1) {
    //      return null;
    //    }
    final ComputationTargetSpecification currencyTarget = ComputationTargetSpecification.of(FinancialSecurityUtils.getCurrency(target.getSecurity()));
    final String yieldCurveName = Iterables.getOnlyElement(yieldCurveNames);
    final String yieldCurveCalculationConfigName = Iterables.getOnlyElement(yieldCurveCalculationConfigNames);
    final String yieldCurveCalculationMethodName = Iterables.getOnlyElement(yieldCurveCalculationMethodNames);
    //    final String spreadCurveName = Iterables.getOnlyElement(spreadCurveNames);
    final ValueRequirement yieldCurveRequirement = YieldCurveFunctionUtils.getCurveRequirement(currencyTarget, yieldCurveName, yieldCurveCalculationConfigName,
        yieldCurveCalculationMethodName);
    final Set<String> creditSpreadCurveShifts = constraints.getValues(PROPERTY_SPREAD_CURVE_SHIFT);
    final ValueProperties.Builder spreadCurveProperties = ValueProperties.builder()
        .with(ValuePropertyNames.CURVE, spreadCurveName);
    if (creditSpreadCurveShifts != null) {
      final Set<String> creditSpreadCurveShiftTypes = constraints.getValues(PROPERTY_SPREAD_CURVE_SHIFT_TYPE);
      if (creditSpreadCurveShiftTypes == null || creditSpreadCurveShiftTypes.size() != 1) {
        return null;
      }
      spreadCurveProperties.with(PROPERTY_SPREAD_CURVE_SHIFT, creditSpreadCurveShifts).with(PROPERTY_SPREAD_CURVE_SHIFT_TYPE, creditSpreadCurveShiftTypes);
    }
    final ValueRequirement creditSpreadCurveRequirement = new ValueRequirement(ValueRequirementNames.CREDIT_SPREAD_CURVE, ComputationTargetSpecification.NULL, spreadCurveProperties.get());
    final ValueRequirement recoveryRateRequirement = new ValueRequirement(MarketDataRequirementNames.MARKET_VALUE, ComputationTargetType.PRIMITIVE, recoveryRateIdentifier.getExternalId());
    return Sets.newHashSet(yieldCurveRequirement, creditSpreadCurveRequirement, recoveryRateRequirement);
  }

  @Override
  public Set<ValueSpecification> getResults(final FunctionCompilationContext context, final ComputationTarget target, final Map<ValueSpecification, ValueRequirement> inputs) {
    final ValueProperties.Builder propertiesBuilder = getCommonResultProperties();
    for (final Map.Entry<ValueSpecification, ValueRequirement> entry : inputs.entrySet()) {
      final ValueSpecification spec = entry.getKey();
      final ValueProperties.Builder inputPropertiesBuilder = spec.getProperties().copy();
      inputPropertiesBuilder.withoutAny(ValuePropertyNames.FUNCTION);
      if (spec.getValueName().equals(ValueRequirementNames.YIELD_CURVE)) {
        propertiesBuilder.with(CreditInstrumentPropertyNamesAndValues.PROPERTY_YIELD_CURVE, inputPropertiesBuilder.get().getValues(ValuePropertyNames.CURVE));
        inputPropertiesBuilder.withoutAny(ValuePropertyNames.CURVE);
        propertiesBuilder.with(CreditInstrumentPropertyNamesAndValues.PROPERTY_YIELD_CURVE_CALCULATION_CONFIG, inputPropertiesBuilder.get().getValues(ValuePropertyNames.CURVE_CALCULATION_CONFIG));
        inputPropertiesBuilder.withoutAny(ValuePropertyNames.CURVE_CALCULATION_CONFIG);
        propertiesBuilder.with(CreditInstrumentPropertyNamesAndValues.PROPERTY_YIELD_CURVE_CALCULATION_METHOD, inputPropertiesBuilder.get().getValues(ValuePropertyNames.CURVE_CALCULATION_METHOD));
        inputPropertiesBuilder.withoutAny(ValuePropertyNames.CURVE_CALCULATION_METHOD);
      } else if (spec.getValueName().equals(ValueRequirementNames.CREDIT_SPREAD_CURVE)) {
        propertiesBuilder.with(CreditInstrumentPropertyNamesAndValues.PROPERTY_SPREAD_CURVE, inputPropertiesBuilder.get().getValues(ValuePropertyNames.CURVE));
        inputPropertiesBuilder.withoutAny(ValuePropertyNames.CURVE);
      }
      if (!inputPropertiesBuilder.get().isEmpty()) {
        for (final String propertyName : inputPropertiesBuilder.get().getProperties()) {
          propertiesBuilder.with(propertyName, inputPropertiesBuilder.get().getValues(propertyName));
        }
      }
    }
    if (labelResultWithCurrency()) {
      propertiesBuilder.with(ValuePropertyNames.CURRENCY, FinancialSecurityUtils.getCurrency(target.getSecurity()).getCode());
    }
    final ValueProperties properties = propertiesBuilder.get();
    final ComputationTargetSpecification targetSpec = target.toSpecification();
    final Set<ValueSpecification> results = new HashSet<>();
    for (final String valueRequirement : _valueRequirements) {
      results.add(new ValueSpecification(valueRequirement, targetSpec, properties));
    }
    return results;
  }

  protected abstract Set<ComputedValue> getComputedValue(CreditDefaultSwapDefinition definition,
                                                         ISDACompliantYieldCurve yieldCurve,
                                                         ZonedDateTime[] times,
                                                         double[] marketSpreads,
                                                         ZonedDateTime valuationTime,
                                                         ComputationTarget target,
                                                         ValueProperties properties,
                                                         FunctionInputs inputs,
                                                         ISDACompliantCreditCurve hazardCurve, CDSAnalytic analytic);

  protected abstract ValueProperties.Builder getCommonResultProperties();

  protected abstract boolean labelResultWithCurrency();

  @Override
  public boolean canHandleMissingInputs() {
    return true;
  }

  @Override
  public boolean canHandleMissingRequirements() {
    return true;
  }

  protected static double getCoupon(final StandardCDSCoupon coupon) {
    switch (coupon) {
      case _25bps:
        return 0.0025;
      case _100bps:
        return 0.01;
      case _125bps:
        return 0.025;
      case _300bps:
        return 0.03;
      case _500bps:
        return 0.05;
      case _750bps:
        return 0.07;
      case _1000bps:
        return 0.1;
      default:
        throw new OpenGammaRuntimeException("Unknown coupon amount: " + coupon.name());
    }
  }

  protected static double getCoupon(final CreditDefaultSwapDefinition definition) {
    if (definition instanceof StandardCreditDefaultSwapDefinition) {
      return getCoupon(((StandardCreditDefaultSwapDefinition) definition).getPremiumLegCoupon());
    } else if (definition instanceof LegacyCreditDefaultSwapDefinition) {
      return 1e-4 * ((LegacyCreditDefaultSwapDefinition) definition).getParSpread();
    } else {
      throw new OpenGammaRuntimeException("Ubnexpected security type: " + definition);
    }
  }
}
