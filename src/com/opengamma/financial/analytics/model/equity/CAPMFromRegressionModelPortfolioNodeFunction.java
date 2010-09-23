/**
 * Copyright (C) 2009 - 2010 by OpenGamma Inc.
 *
 * Please see distribution for license.
 */
package com.opengamma.financial.analytics.model.equity;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.opengamma.engine.ComputationTarget;
import com.opengamma.engine.ComputationTargetType;
import com.opengamma.engine.function.AbstractFunction;
import com.opengamma.engine.function.FunctionCompilationContext;
import com.opengamma.engine.function.FunctionExecutionContext;
import com.opengamma.engine.function.FunctionInputs;
import com.opengamma.engine.function.FunctionInvoker;
import com.opengamma.engine.position.PortfolioNode;
import com.opengamma.engine.value.ComputedValue;
import com.opengamma.engine.value.ValueRequirement;
import com.opengamma.engine.value.ValueRequirementNames;
import com.opengamma.engine.value.ValueSpecification;

/**
 * 
 */
public class CAPMFromRegressionModelPortfolioNodeFunction extends AbstractFunction implements FunctionInvoker {
  private static final Double NOT_CALCULATED = -99999999999999.;

  @Override
  public Set<ComputedValue> execute(final FunctionExecutionContext executionContext, final FunctionInputs inputs, final ComputationTarget target, final Set<ValueRequirement> desiredValues) {
    final Set<ComputedValue> result = new HashSet<ComputedValue>();
    final PortfolioNode node = target.getPortfolioNode();
    result.add(new ComputedValue(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_ADJUSTED_R_SQUARED, node), getUniqueIdentifier()), NOT_CALCULATED));
    result.add(new ComputedValue(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_ALPHA, node), getUniqueIdentifier()), NOT_CALCULATED));
    result.add(new ComputedValue(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_BETA, node), getUniqueIdentifier()), NOT_CALCULATED));
    result.add(new ComputedValue(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_MEAN_SQUARE_ERROR, node), getUniqueIdentifier()), NOT_CALCULATED));
    result.add(new ComputedValue(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_ALPHA_PVALUES, node), getUniqueIdentifier()), NOT_CALCULATED));
    result.add(new ComputedValue(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_BETA_PVALUES, node), getUniqueIdentifier()), NOT_CALCULATED));
    result.add(new ComputedValue(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_R_SQUARED, node), getUniqueIdentifier()), NOT_CALCULATED));
    result.add(new ComputedValue(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_ALPHA_RESIDUALS, node), getUniqueIdentifier()), NOT_CALCULATED));
    result.add(new ComputedValue(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_BETA_RESIDUALS, node), getUniqueIdentifier()), NOT_CALCULATED));
    result.add(new ComputedValue(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_STANDARD_ERROR_OF_ALPHA, node), getUniqueIdentifier()), NOT_CALCULATED));
    result.add(new ComputedValue(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_STANDARD_ERROR_OF_BETA, node), getUniqueIdentifier()), NOT_CALCULATED));
    result.add(new ComputedValue(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_ALPHA_TSTATS, node), getUniqueIdentifier()), NOT_CALCULATED));
    result.add(new ComputedValue(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_BETA_TSTATS, node), getUniqueIdentifier()), NOT_CALCULATED));
    return result;
  }

  @Override
  public boolean canApplyTo(final FunctionCompilationContext context, final ComputationTarget target) {
    return target.getType() == ComputationTargetType.PORTFOLIO_NODE;
  }

  @Override
  public Set<ValueRequirement> getRequirements(final FunctionCompilationContext context, final ComputationTarget target) {
    return Collections.<ValueRequirement> emptySet();
  }

  @Override
  public Set<ValueSpecification> getResults(final FunctionCompilationContext context, final ComputationTarget target) {
    if (canApplyTo(context, target)) {
      final Set<ValueSpecification> results = new HashSet<ValueSpecification>();
      final PortfolioNode node = target.getPortfolioNode();
      results.add(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_ADJUSTED_R_SQUARED, node), getUniqueIdentifier()));
      results.add(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_ALPHA, node), getUniqueIdentifier()));
      results.add(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_BETA, node), getUniqueIdentifier()));
      results.add(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_MEAN_SQUARE_ERROR, node), getUniqueIdentifier()));
      results.add(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_ALPHA_PVALUES, node), getUniqueIdentifier()));
      results.add(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_BETA_PVALUES, node), getUniqueIdentifier()));
      results.add(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_R_SQUARED, node), getUniqueIdentifier()));
      results.add(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_ALPHA_RESIDUALS, node), getUniqueIdentifier()));
      results.add(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_BETA_RESIDUALS, node), getUniqueIdentifier()));
      results.add(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_STANDARD_ERROR_OF_ALPHA, node), getUniqueIdentifier()));
      results.add(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_STANDARD_ERROR_OF_BETA, node), getUniqueIdentifier()));
      results.add(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_ALPHA_TSTATS, node), getUniqueIdentifier()));
      results.add(new ValueSpecification(new ValueRequirement(ValueRequirementNames.CAPM_BETA_TSTATS, node), getUniqueIdentifier()));
      return results;
    }
    return null;
  }

  @Override
  public String getShortName() {
    return "CAPM_RegressionPortfolioNodeModel";
  }

  @Override
  public ComputationTargetType getTargetType() {
    return ComputationTargetType.PORTFOLIO_NODE;
  }

}
