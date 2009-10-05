/**
 * Copyright (C) 2009 - 2009 by OpenGamma Inc.
 * 
 * Please see distribution for license.
 */
package com.opengamma.financial.timeseries.returns;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;

import javax.time.InstantProvider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.opengamma.timeseries.ArrayDoubleTimeSeries;
import com.opengamma.timeseries.DoubleTimeSeries;
import com.opengamma.util.CalculationMode;

/**
 * 
 * @author emcleod
 */
public class ContinuouslyCompoundedRelativeTimeSeriesReturnCalculator extends RelativeTimeSeriesReturnCalculator {
  private static final Logger s_Log = LoggerFactory.getLogger(ContinuouslyCompoundedRelativeTimeSeriesReturnCalculator.class);

  public ContinuouslyCompoundedRelativeTimeSeriesReturnCalculator(final CalculationMode mode) {
    super(mode);
  }

  @Override
  public DoubleTimeSeries evaluate(final DoubleTimeSeries... x) {
    if (x.length > 2) {
      s_Log.info("Have more than two time series in array; only using first two");
    }
    final DoubleTimeSeries ts1 = x[0];
    final DoubleTimeSeries ts2 = x[1];
    final List<InstantProvider> times = new ArrayList<InstantProvider>();
    final List<Double> returns = new ArrayList<Double>();
    final Iterator<Entry<InstantProvider, Double>> iter1 = ts1.iterator();
    final Iterator<Entry<InstantProvider, Double>> iter2 = ts2.iterator();
    Entry<InstantProvider, Double> entry1, entry2;
    while (iter1.hasNext()) {
      entry1 = iter1.next();
      entry2 = iter2.next();
      times.add(entry1.getKey());
      returns.add(Math.log(entry1.getValue() / entry2.getValue()));
    }
    return new ArrayDoubleTimeSeries(times, returns);
  }
}
