/**
 * Copyright (C) 2009 - 2010 by OpenGamma Inc.
 *
 * Please see distribution for license.
 */
package com.opengamma.engine.view.client;

import java.util.Map;

import com.opengamma.engine.ComputationTargetSpecification;
import com.opengamma.engine.value.ComputedValue;
import com.opengamma.engine.view.DeltaDefinition;
import com.opengamma.engine.view.ViewCalculationResultModel;
import com.opengamma.engine.view.ViewDefinition;
import com.opengamma.engine.view.ViewDeltaResultModel;
import com.opengamma.engine.view.ViewDeltaResultModelImpl;
import com.opengamma.engine.view.ViewResultModel;

/**
 * Produces {@link ViewDeltaResultModel} instances by comparing two {@link ViewComputationResultModel}.
 */
public class ViewDeltaResultCalculator {

  /**
   * Computes the delta between and old and new results.
   * 
   * @param viewDefinition  the view definition to which the results apply
   * @param previousResult  the previous result
   * @param result  the new result
   * @return  the delta between the two results, not null
   */
  public static ViewDeltaResultModel computeDeltaModel(ViewDefinition viewDefinition, ViewResultModel previousResult, ViewResultModel result) {
    ViewDeltaResultModelImpl deltaModel = new ViewDeltaResultModelImpl();
    deltaModel.setValuationTime(result.getValuationTime());
    deltaModel.setResultTimestamp(result.getResultTimestamp());
    deltaModel.setPreviousResultTimestamp(previousResult.getResultTimestamp());
    deltaModel.setCalculationConfigurationNames(result.getCalculationConfigurationNames());
    for (ComputationTargetSpecification targetSpec : result.getAllTargets()) {
      computeDeltaModel(viewDefinition, deltaModel, targetSpec, previousResult, result);
    }
    
    return deltaModel;
  }
  
  private static void computeDeltaModel(ViewDefinition viewDefinition, ViewDeltaResultModelImpl deltaModel, ComputationTargetSpecification targetSpec,
      ViewResultModel previousResult, ViewResultModel result) {
    for (String calcConfigName : result.getCalculationConfigurationNames()) {
      DeltaDefinition deltaDefinition = viewDefinition.getCalculationConfiguration(calcConfigName).getDeltaDefinition();
      ViewCalculationResultModel resultCalcModel = result.getCalculationResult(calcConfigName);
      ViewCalculationResultModel previousCalcModel = previousResult.getCalculationResult(calcConfigName);      
      computeDeltaModel(deltaDefinition, deltaModel, targetSpec, calcConfigName, previousCalcModel, resultCalcModel);
    }
  }

  private static void computeDeltaModel(DeltaDefinition deltaDefinition, ViewDeltaResultModelImpl deltaModel, ComputationTargetSpecification targetSpec,
      String calcConfigName, ViewCalculationResultModel previousCalcModel, ViewCalculationResultModel resultCalcModel) {
    if (previousCalcModel == null) {
      // Everything is new/delta because this is a new calculation context.
      Map<String, ComputedValue> resultValues = resultCalcModel.getValues(targetSpec);
      for (Map.Entry<String, ComputedValue> resultEntry : resultValues.entrySet()) {
        deltaModel.addValue(calcConfigName, resultEntry.getValue());
      }
    } else {
      Map<String, ComputedValue> resultValues = resultCalcModel.getValues(targetSpec);
      Map<String, ComputedValue> previousValues = previousCalcModel.getValues(targetSpec);
      
      if (previousValues == null) {
        // Everything is new/delta because this is a new target.
        for (Map.Entry<String, ComputedValue> resultEntry : resultValues.entrySet()) {
          deltaModel.addValue(calcConfigName, resultEntry.getValue());
        }
      } else {
        // Have to individual delta.
        for (Map.Entry<String, ComputedValue> resultEntry : resultValues.entrySet()) {
          ComputedValue resultValue = resultEntry.getValue();
          ComputedValue previousValue = previousValues.get(resultEntry.getKey());
          // REVIEW jonathan 2010-05-07 -- The previous value that we're comparing with is the value from the last
          // computation cycle, not the value that we last emitted as a delta. It is therefore important that the
          // DeltaComparers take this into account in their implementation of isDelta. E.g. they should compare the
          // values after truncation to the required decimal place, rather than testing whether the difference of the
          // full values is greater than some threshold; this way, there will always be a point beyond which a change
          // is detected, even in the event of gradual creep.
          if (deltaDefinition.isDelta(previousValue, resultValue)) {
            deltaModel.addValue(calcConfigName, resultEntry.getValue());
          }
        }
      }
    }
  }
  
}
