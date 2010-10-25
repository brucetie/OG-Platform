/**
 * Copyright (C) 2009 - 2009 by OpenGamma Inc.
 * 
 * Please see distribution for license.
 */
package com.opengamma.engine.function;

import java.util.Set;

import javax.time.Instant;

import com.opengamma.engine.ComputationTarget;
import com.opengamma.engine.ComputationTargetType;
import com.opengamma.engine.value.ValueRequirement;
import com.opengamma.engine.value.ValueSpecification;
import com.opengamma.util.PublicSPI;

/**
 * A single unit of work capable of operating on inputs to produce results, configured and 
 * ready to execute as at a particular time.
 */
@PublicSPI
public interface CompiledFunctionDefinition {

  /**
   * Returns the underlying {@link FunctionDefinition} that was used to create this
   * instance.
   * 
   * @return the original definition
   */
  FunctionDefinition getFunctionDefinition();

  /**
   * Obtain the core {@link ComputationTargetType} that this function instance is configured
   * to support.
   * While this can be determined by the subgraph, it is provided at this
   * level for ease of programming, and for performance purposes.
   *  
   * @return The target type to which this instance can apply.
   */
  ComputationTargetType getTargetType();

  /**
   * Determine whether this function instance is capable of operating on the specified target.
   * 
   * @param context The compilation context with view-specific parameters and configurations.
   * @param target The target for which calculation is desired.
   * @return {@code true} iff this function can produce results for the specified target.
   */
  boolean canApplyTo(FunctionCompilationContext context, ComputationTarget target);

  /**
   * Obtain all input requirements necessary for the operation of this function at execution time.
   * 
   * @param context The compilation context with view-specific parameters and configurations.
   * @param target The target for which calculation is desired.
   * @return All input requirements to execute this function on the specified target with the specified configuration.
   */
  Set<ValueRequirement> getRequirements(FunctionCompilationContext context, ComputationTarget target);

  // See ENG-216
  /**
   * Determine the known-to-be live data inputs to this function.
   * In general, implementations <b>should not</b> override the implementation
   * in {@link AbstractFunction}. This method is deprecated and will be removed.
   * @return Required live data for this function.
   */
  Set<ValueSpecification> getRequiredLiveData();

  /**
   * Determine which result values can be produced by this function when applied to the
   * specified target assuming no input constraints.
   * Should return the <b>maximal</b> set of potential outputs. <b>Actual</b> computed values
   * will be trimmed.
   * 
   * @param context The compilation context with view-specific parameters and configurations.
   * @param target The target for which calculation is desired.
   * @return All results <b>possible</b> to be computed by this function for this target with these parameters.
   */
  Set<ValueSpecification> getResults(FunctionCompilationContext context, ComputationTarget target);
  
  /**
   * Determine which result values can be produced by this function when applied to the
   * specified target given the resolved inputs. Should return the <b>maximal</b> set of potential outputs.
   * <b>Actual</b> computed values will be trimmed. The default implementation from {@link AbstractFunction}
   * will return the same value as {@link #getResults (FunctionCompilationContext, ComputationTarget)}. If
   * a function specified both its outputs and inputs using a wildcard, with the outputs depending on the
   * inputs, it should override this to implement that dependency. If it is not possible to generate any
   * results using the inputs given, an empty set must be returned.
   * 
   * @param context The compilation context with view-specific parameters and configurations.
   * @param target The target for which calculation is desired.
   * @param inputs The resolved inputs to the function.
   * @return All results <b>possible</b> to be computed by this function for this target with these parameters.
   */
  Set<ValueSpecification> getResults(FunctionCompilationContext context, ComputationTarget target, Set<ValueSpecification> inputs);

  /**
   * Returns an invocation handle to the compiled function. If the function is not available at this node,
   * for example because it requires a native library, {@code null} may be returned. It is not necessary for
   * an implementation to cache the invoker objects.
   * 
   * @return the function invoker
   */
  FunctionInvoker getFunctionInvoker();

  /**
   * States the earliest time that this metadata and invoker will be valid for. If the definition is always
   * valid returns {@code null}.
   * 
   * @return the earliest timestamp. 
   */
  Instant getEarliestInvocationTime();

  /**
   * States the latest time that this metadata and invoker will be valid for. If the definition is always
   * valid returns {@code null}.
   * 
   * @return the latest timestamp.
   */
  Instant getLatestInvocationTime();

}
