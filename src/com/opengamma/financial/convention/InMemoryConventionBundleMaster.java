/**
 * Copyright (C) 2009 - 2010 by OpenGamma Inc.
 *
 * Please see distribution for license.
 */
package com.opengamma.financial.convention;

import static com.opengamma.id.IdentificationScheme.BLOOMBERG_TICKER;

import java.util.ArrayList;
import java.util.Collection;

import com.opengamma.financial.convention.businessday.BusinessDayConvention;
import com.opengamma.financial.convention.businessday.BusinessDayConventionFactory;
import com.opengamma.financial.convention.daycount.DayCount;
import com.opengamma.financial.convention.daycount.DayCountFactory;
import com.opengamma.financial.convention.frequency.Frequency;
import com.opengamma.financial.convention.frequency.SimpleFrequencyFactory;
import com.opengamma.id.IdentificationScheme;
import com.opengamma.id.Identifier;
import com.opengamma.id.IdentifierBundle;
import com.opengamma.id.IdentifierBundleMapper;
import com.opengamma.id.UniqueIdentifier;
/**
 * An in-memory, statically initialized master for convention bundles and their meta-data
 */
public class InMemoryConventionBundleMaster implements ConventionBundleMaster {
  /**
   * IdentificationScheme to use when specifying rates with simple descriptions e.g. 'LIBOR O/N', 'LIBOR 1w' etc.
   */
  public static final IdentificationScheme SIMPLE_NAME_SCHEME = new IdentificationScheme("Reference Rate Simple Name");
  
  /**
   * IdentificationScheme of the unique identifiers generated by this repository.
   */
  public static final IdentificationScheme IN_MEMORY_UNIQUE_SCHEME = new IdentificationScheme("In-memory Reference Rate unique");
  
  private final IdentifierBundleMapper<ConventionBundle> _mapper = new IdentifierBundleMapper<ConventionBundle>(IN_MEMORY_UNIQUE_SCHEME.getName());
  
  public InMemoryConventionBundleMaster() {
    //CSOFF
    // NOTE THESE ONLY APPLY TO US LIBOR RATES
    final BusinessDayConvention modified = BusinessDayConventionFactory.INSTANCE.getBusinessDayConvention("Modified");
    final BusinessDayConvention following = BusinessDayConventionFactory.INSTANCE.getBusinessDayConvention("Following");
    final DayCount actact = DayCountFactory.INSTANCE.getDayCount("Actual/Actual");
    final DayCount act360 = DayCountFactory.INSTANCE.getDayCount("Actual/360");
    final Frequency freq = null;
    addConventionBundle(IdentifierBundle.of(Identifier.of(BLOOMBERG_TICKER, "US00O/N Index"), Identifier.of(SIMPLE_NAME_SCHEME, "LIBOR O/N")), "LIBOR O/N", actact, following, freq, 0);
    addConventionBundle(IdentifierBundle.of(Identifier.of(BLOOMBERG_TICKER, "US00T/N Index"), Identifier.of(SIMPLE_NAME_SCHEME, "LIBOR T/N")), "LIBOR T/N", actact, following, freq, 0);
    addConventionBundle(IdentifierBundle.of(Identifier.of(BLOOMBERG_TICKER, "US0001W Index"), Identifier.of(SIMPLE_NAME_SCHEME, "LIBOR 1w")), "LIBOR 1w", actact, following, freq, 2);
    addConventionBundle(IdentifierBundle.of(Identifier.of(BLOOMBERG_TICKER, "US0002W Index"), Identifier.of(SIMPLE_NAME_SCHEME, "LIBOR 2w")), "LIBOR 2w", actact, following, freq, 2);
    addConventionBundle(IdentifierBundle.of(Identifier.of(BLOOMBERG_TICKER, "US0001M Index"), Identifier.of(SIMPLE_NAME_SCHEME, "LIBOR 1m")), "LIBOR 1m", actact, modified, freq, 2);
    addConventionBundle(IdentifierBundle.of(Identifier.of(BLOOMBERG_TICKER, "US0002M Index"), Identifier.of(SIMPLE_NAME_SCHEME, "LIBOR 2m")), "LIBOR 2m", actact, modified, freq, 2);
    addConventionBundle(IdentifierBundle.of(Identifier.of(BLOOMBERG_TICKER, "US0003M Index"), Identifier.of(SIMPLE_NAME_SCHEME, "LIBOR 3m")), "LIBOR 3m", actact, modified, freq, 2);
    addConventionBundle(IdentifierBundle.of(Identifier.of(BLOOMBERG_TICKER, "US0004M Index"), Identifier.of(SIMPLE_NAME_SCHEME, "LIBOR 4m")), "LIBOR 4m", actact, modified, freq, 2);
    addConventionBundle(IdentifierBundle.of(Identifier.of(BLOOMBERG_TICKER, "US0005M Index"), Identifier.of(SIMPLE_NAME_SCHEME, "LIBOR 5m")), "LIBOR 5m", actact, modified, freq, 2);
    addConventionBundle(IdentifierBundle.of(Identifier.of(BLOOMBERG_TICKER, "US0006M Index"), Identifier.of(SIMPLE_NAME_SCHEME, "LIBOR 6m")), "LIBOR 6m", actact, modified, freq, 2);
    addConventionBundle(IdentifierBundle.of(Identifier.of(BLOOMBERG_TICKER, "US0007M Index"), Identifier.of(SIMPLE_NAME_SCHEME, "LIBOR 7m")), "LIBOR 7m", actact, modified, freq, 2);
    addConventionBundle(IdentifierBundle.of(Identifier.of(BLOOMBERG_TICKER, "US0008M Index"), Identifier.of(SIMPLE_NAME_SCHEME, "LIBOR 8m")), "LIBOR 8m", actact, modified, freq, 2);
    addConventionBundle(IdentifierBundle.of(Identifier.of(BLOOMBERG_TICKER, "US0009M Index"), Identifier.of(SIMPLE_NAME_SCHEME, "LIBOR 9m")), "LIBOR 9m", actact, modified, freq, 2);
    addConventionBundle(IdentifierBundle.of(Identifier.of(BLOOMBERG_TICKER, "US0010M Index"), Identifier.of(SIMPLE_NAME_SCHEME, "LIBOR 10m")), "LIBOR 10m", actact, modified, freq, 2);
    addConventionBundle(IdentifierBundle.of(Identifier.of(BLOOMBERG_TICKER, "US0011M Index"), Identifier.of(SIMPLE_NAME_SCHEME, "LIBOR 11m")), "LIBOR 11m", actact, modified, freq, 2);
    addConventionBundle(IdentifierBundle.of(Identifier.of(BLOOMBERG_TICKER, "US0012M Index"), Identifier.of(SIMPLE_NAME_SCHEME, "LIBOR 12m")), "LIBOR 12m", actact, modified, freq, 2);
    
    final DayCount thirty360 = DayCountFactory.INSTANCE.getDayCount("30/360");
    final Frequency semiAnnual = SimpleFrequencyFactory.INSTANCE.getFrequency(Frequency.SEMI_ANNUAL_NAME);
    final Frequency quarterly = SimpleFrequencyFactory.INSTANCE.getFrequency(Frequency.QUARTERLY_NAME);
    addConventionBundle(IdentifierBundle.of(Identifier.of(SIMPLE_NAME_SCHEME, "USD_SWAP")), "USD_SWAP", thirty360, following, semiAnnual, 2, act360, following, quarterly, 2, Identifier.of(SIMPLE_NAME_SCHEME, "LIBOR 3m") );
    
    addConventionBundle(IdentifierBundle.of(Identifier.of(SIMPLE_NAME_SCHEME, "USD_FRA")), "USD_FRA", act360, following, null, 2);
    
    addConventionBundle(IdentifierBundle.of(Identifier.of(SIMPLE_NAME_SCHEME, "USD_IRFUTURE")), "USD_IRFUTURE", act360, following, null, 2, 0.25);
  }
  
  @Override
  public synchronized UniqueIdentifier addConventionBundle(final IdentifierBundle bundle, final String name, final DayCount dayCount,
                                                           final BusinessDayConvention businessDayConvention, final Frequency frequency, 
                                                           final int settlementDays) {
    final ConventionBundleImpl refRate = new ConventionBundleImpl(bundle, name, dayCount, businessDayConvention, frequency, settlementDays);
    final UniqueIdentifier uid = _mapper.add(bundle, refRate);
    refRate.setUniqueIdentifier(uid);
    return uid;
  }
  
  public synchronized UniqueIdentifier addConventionBundle(final IdentifierBundle bundle, final String name, final DayCount dayCount,
                                                           final BusinessDayConvention businessDayConvention, final Frequency frequency, 
                                                           final int settlementDays, final double pointValue) {
    final ConventionBundleImpl refRate = new ConventionBundleImpl(bundle, name, dayCount, businessDayConvention, frequency, settlementDays, pointValue);
    final UniqueIdentifier uid = _mapper.add(bundle, refRate);
    refRate.setUniqueIdentifier(uid);
    return uid;
  }
  
  @Override
  public synchronized UniqueIdentifier addConventionBundle(final IdentifierBundle bundle, final String name, 
                                                           final DayCount swapFixedLegDayCount, final BusinessDayConvention swapFixedLegBusinessDayConvention, final Frequency swapFixedLegFrequency, final Integer swapFixedLegSettlementDays,
                                                           final DayCount swapFloatingLegDayCount, final BusinessDayConvention swapFloatingLegBusinessDayConvention, final Frequency swapFloatingLegFrequency, final Integer swapFloatingLegSettlementDays,
                                                           final Identifier swapFloatingLegInitialRate) {
    final ConventionBundleImpl refRate = new ConventionBundleImpl(bundle, name, swapFixedLegDayCount, swapFixedLegBusinessDayConvention, swapFixedLegFrequency, swapFixedLegSettlementDays,
                                                            swapFloatingLegDayCount, swapFloatingLegBusinessDayConvention, swapFloatingLegFrequency, swapFloatingLegSettlementDays, swapFloatingLegInitialRate);
    final UniqueIdentifier uid = _mapper.add(bundle, refRate);
    refRate.setUniqueIdentifier(uid);
    return uid;
  }

  @Override
  public ConventionBundleDocument getConventionBundle(final UniqueIdentifier uniqueIdentifier) {
    return new ConventionBundleDocument(_mapper.get(uniqueIdentifier));
  }
  
  @Override
  public ConventionBundleSearchResult searchConventionBundle(final ConventionBundleSearchRequest request) {
    final Collection<ConventionBundle> collection = _mapper.get(request.getIdentifiers());
    return new ConventionBundleSearchResult(wrapReferenceRatesWithDocuments(collection));
  }
  
  @Override
  public ConventionBundleSearchResult searchHistoricConventionBundle(final ConventionBundleSearchHistoricRequest request) {
    final Collection<ConventionBundle> collection = _mapper.get(request.getIdentifiers());
    return new ConventionBundleSearchResult(wrapReferenceRatesWithDocuments(collection));
  }
  
  private Collection<ConventionBundleDocument> wrapReferenceRatesWithDocuments(final Collection<ConventionBundle> referenceRates) {
    final Collection<ConventionBundleDocument> results = new ArrayList<ConventionBundleDocument>(referenceRates.size());
    for (final ConventionBundle referenceRate : referenceRates) {
      results.add(new ConventionBundleDocument(referenceRate));
    }
    return results;
  }
}
