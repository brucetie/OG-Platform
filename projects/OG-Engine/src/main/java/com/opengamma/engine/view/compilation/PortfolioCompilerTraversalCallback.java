/**
 * Copyright (C) 2009 - present by OpenGamma Inc. and the OpenGamma group of companies
 *
 * Please see distribution for license.
 */
package com.opengamma.engine.view.compilation;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.google.common.collect.Sets;
import com.opengamma.core.position.PortfolioNode;
import com.opengamma.core.position.Position;
import com.opengamma.core.position.Trade;
import com.opengamma.core.position.impl.AbstractPortfolioNodeTraversalCallback;
import com.opengamma.core.security.Security;
import com.opengamma.core.security.SecurityLink;
import com.opengamma.engine.ComputationTargetSpecification;
import com.opengamma.engine.MemoryUtils;
import com.opengamma.engine.depgraph.DependencyGraphBuilder;
import com.opengamma.engine.target.ComputationTargetReference;
import com.opengamma.engine.target.ComputationTargetRequirement;
import com.opengamma.engine.target.ComputationTargetType;
import com.opengamma.engine.value.ValueProperties;
import com.opengamma.engine.value.ValueRequirement;
import com.opengamma.engine.view.ResultModelDefinition;
import com.opengamma.engine.view.ResultOutputMode;
import com.opengamma.engine.view.ViewCalculationConfiguration;
import com.opengamma.id.UniqueId;
import com.opengamma.util.tuple.Pair;

/**
 * Portfolio tree traversal callback methods that construct value requirements for the specified portfolio's nodes, positions and trades (as per options specified in the result model definition). The
 * value requirements are added to the specified dependency graph builder, possibly triggering the background compilation of dependency graphs for each stage in a portfolio tree while this traversal
 * is still ongoing. The pre-order method for a portfolio node sets up an empty requirements container for that node, which is filled up as its children are traversed (if aggregation is specified in
 * the result model definition), and then added to the dependency graph's list of targets in the post-order method for that portfolio node.
 */
/* package */final class PortfolioCompilerTraversalCallback extends AbstractPortfolioNodeTraversalCallback {

  private static final class NodeData {

    private final ComputationTargetSpecification _targetSpec;
    private final Set<Pair<String, ValueProperties>> _requirements = Sets.newHashSet();

    public NodeData(final PortfolioNode node) {
      _targetSpec = ComputationTargetSpecification.of(node);
    }

    public synchronized void addRequirements(final Set<Pair<String, ValueProperties>> requirements) {
      _requirements.addAll(requirements);
    }

    public Set<Pair<String, ValueProperties>> getRequirements() {
      return _requirements;
    }

    public ComputationTargetSpecification getTargetSpecification() {
      return _targetSpec;
    }

  }

  private final Set<UniqueId> _includeEvents;
  private final Set<UniqueId> _excludeEvents;
  private Map<String, Set<Pair<String, ValueProperties>>> _portfolioRequirementsBySecurityType;
  private final ResultModelDefinition _resultModelDefinition;
  private final DependencyGraphBuilder _builder;
  private final ConcurrentMap<ComputationTargetReference, UniqueId> _resolutions;

  /**
   * This map persists gathered information for each portfolio node and position across multiple traversal steps, thus allowing child nodes/positions to insert aggregate requirements into their parent
   * node.
   */
  private final ConcurrentMap<UniqueId, NodeData> _nodeData = new ConcurrentHashMap<UniqueId, NodeData>();

  public PortfolioCompilerTraversalCallback(final ViewCalculationConfiguration calculationConfiguration, final DependencyGraphBuilder builder,
      final ConcurrentMap<ComputationTargetReference, UniqueId> resolutions, final Set<UniqueId> includeEvents, final Set<UniqueId> excludeEvents) {
    _portfolioRequirementsBySecurityType = calculationConfiguration.getPortfolioRequirementsBySecurityType();
    _resultModelDefinition = calculationConfiguration.getViewDefinition().getResultModelDefinition();
    _builder = builder;
    _resolutions = resolutions;
    _includeEvents = includeEvents;
    _excludeEvents = excludeEvents;
  }

  public Map<String, Set<Pair<String, ValueProperties>>> getPortfolioRequirementsBySecurityType() {
    return _portfolioRequirementsBySecurityType;
  }

  public void setPortfolioRequirementsBySecurityType(Map<String, Set<Pair<String, ValueProperties>>> portfolioRequirementsBySecurityType) {
    _portfolioRequirementsBySecurityType = portfolioRequirementsBySecurityType;
  }

  public void reset() {
    _nodeData.clear();
  }

  /**
   * Add the specified value requirement to the dep graph builder, triggering graph building by background threads
   * 
   * @param valueRequirement the value requirement to add
   */
  protected void addValueRequirement(final ValueRequirement valueRequirement) {
    _builder.addTarget(valueRequirement);
  }

  /**
   * Store details of the security link in the resolution cache. The link is assumed to be a record of the link to the object, for example is it held by strong (object id) or weak (external id)
   * reference.
   * <p>
   * Securities are already resolved when the functions see the positions, so the logging target resolver will not capture any uses of the security.
   * 
   * @param link the link to store - the identifier is taken from this along with the resolved unique identifier
   */
  private void store(final SecurityLink link) {
    final ComputationTargetReference key;
    final UniqueId uid;
    if (link.getTarget() != null) {
      uid = link.getTarget().getUniqueId();
      if (link.getObjectId() != null) {
        key = new ComputationTargetSpecification(ComputationTargetType.SECURITY, uid.toLatest());
      } else if (!link.getExternalId().isEmpty()) {
        key = new ComputationTargetRequirement(ComputationTargetType.SECURITY, link.getExternalId());
      } else {
        return;
      }
      final UniqueId existing = _resolutions.putIfAbsent(MemoryUtils.instance(key), uid);
      assert (existing == null) || existing.equals(uid);
    }
  }

  /**
   * Store details of the position lookup in the resolution cache. Positions are referenced from portfolio nodes by object identifier.
   * 
   * @param
   */
  private void store(final Position position) {
    _resolutions.putIfAbsent(MemoryUtils.instance(new ComputationTargetSpecification(ComputationTargetType.POSITION, position.getUniqueId().toLatest())), position.getUniqueId());
  }

  /**
   * The pre-order operation for a portfolio node, which adds the aggregate value requirements for the current portfolio node to the graph builder's set of value requirements.
   * 
   * @param node the portfolio node being traversed
   */
  @Override
  public void preOrderOperation(final PortfolioNode node) {
    // If a sub-set of nodes is to be considered, fail/return quickly
    if (_excludeEvents != null) {
      if (_excludeEvents.contains(node.getUniqueId())) {
        return;
      }
    }
    // Initialise an empty set of requirements for the current portfolio node
    // This will be filled in as the traversal of this portfolio node's children proceeds, and retrieved during
    // this portfolio node's post-order traversal.
    final NodeData nodeData = new NodeData(node);
    _nodeData.put(node.getUniqueId(), nodeData);
    // Retrieve the required aggregate outputs (by 'aggregate' sec type) for the current calc configuration
    final Set<Pair<String, ValueProperties>> requiredOutputs =
        _portfolioRequirementsBySecurityType.get(ViewCalculationConfiguration.SECURITY_TYPE_AGGREGATE_ONLY);
    if ((requiredOutputs != null) && !requiredOutputs.isEmpty()) {
      // Add the aggregate value requirements for the current portfolio node to the graph builder's set of value requirements,
      // building them using the retrieved required aggregate outputs and the newly created computation target spec
      // for this portfolio node.
      final ComputationTargetSpecification targetSpec = nodeData.getTargetSpecification();
      for (final Pair<String, ValueProperties> requiredOutput : requiredOutputs) {
        addValueRequirement(new ValueRequirement(requiredOutput.getFirst(), targetSpec, requiredOutput.getSecond()));
      }
    }
  }

  /**
   * The pre-order operation for a position in a portfolio. which adds the value requirements for the current position and/or its trades to the graph builder's set of value requirements (if the result
   * model specifies it), and also adds aggregate value requirements to the parent's requirements (again, if the result model specifies it) to be reaped post-order.
   * 
   * @param position the position being traversed
   */
  @Override
  public void preOrderOperation(final PortfolioNode parentNode, final Position position) {
    // If a sub-set of positions is to be considered, fail/return quickly
    if (_includeEvents != null) {
      if (!_includeEvents.contains(position.getUniqueId())) {
        return;
      }
    } else if (_excludeEvents != null) {
      if (_excludeEvents.contains(parentNode.getUniqueId())) {
        return;
      }
    }

    // Get this position's security or return immediately if not available
    final Security security = position.getSecurity();
    if (security == null) {
      return;
    }
    store(position);
    store(position.getSecurityLink());

    // Identify this position's security type
    final String securityType = security.getSecurityType();

    Set<Pair<String, ValueProperties>> requiredOutputs;

    // Are we interested in producing results for positions?
    if ((_resultModelDefinition.getAggregatePositionOutputMode() != ResultOutputMode.NONE)
        || (_resultModelDefinition.getPositionOutputMode() != ResultOutputMode.NONE)) {

      // Get all known required outputs for this security type in the current calculation configuration
      requiredOutputs = _portfolioRequirementsBySecurityType.get(securityType);

      // Check that there's at least one required output to deal with
      if ((requiredOutputs != null) && !requiredOutputs.isEmpty()) {
        final NodeData nodeData = _nodeData.get(parentNode.getUniqueId());
        // Are we interested in aggregate results for the parent? If so, pass on requirements to parent portfolio node
        if (_resultModelDefinition.getAggregatePositionOutputMode() != ResultOutputMode.NONE) {
          nodeData.addRequirements(requiredOutputs);
        }
        // Are we interested in any results at all for this position?
        if (_resultModelDefinition.getPositionOutputMode() != ResultOutputMode.NONE) {
          final ComputationTargetSpecification positionSpec = nodeData.getTargetSpecification().containing(ComputationTargetType.POSITION, position.getUniqueId().toLatest());
          // Add the value requirements for the current position to the graph builder's set of value requirements,
          // building them using the retrieved required outputs for this security type and the newly created computation
          // target spec for this position.
          for (final Pair<String, ValueProperties> requiredOutput : requiredOutputs) {
            addValueRequirement(new ValueRequirement(requiredOutput.getFirst(), positionSpec, requiredOutput.getSecond()));
          }
        }
      }
    }
    final Collection<Trade> trades = position.getTrades();
    if (!trades.isEmpty()) {
      if (_resultModelDefinition.getTradeOutputMode() != ResultOutputMode.NONE) {
        requiredOutputs = _portfolioRequirementsBySecurityType.get(securityType);

        // Check that there's at least one required output to deal with
        if ((requiredOutputs != null) && !requiredOutputs.isEmpty()) {

          // Add value requirements for each trade
          for (final Trade trade : trades) {
            // TODO: [PLAT-2286] Scope the trade underneath it's parent portfolio node and position
            final ComputationTargetSpecification tradeSpec = ComputationTargetSpecification.of(trade);

            // Add the value requirements for the current trade to the graph builder's set of value requirements,
            // building them using the retrieved required outputs icw trades for this security type and the newly
            // created computation target spec for this trade.
            for (final Pair<String, ValueProperties> requiredOutput : requiredOutputs) {
              addValueRequirement(new ValueRequirement(requiredOutput.getFirst(), tradeSpec, requiredOutput.getSecond()));
            }
          }
        }
      }
      for (final Trade trade : position.getTrades()) {
        store(trade.getSecurityLink());
      }
    }
  }

  /**
   * The post-order operation for a portfolio node, which adds the value requirements gathered while traversing this portfolio node's children to the graph builder's set of value requirements. This
   * portfolio node's requirements are also passed up into its own parent node's requirments.
   * 
   * @param node the portfolio node being traversed
   */
  @Override
  public void postOrderOperation(final PortfolioNode node) {
    // Retrieve this portfolio node's value requirements (gathered during traversal of this portfolio node's children)
    final NodeData nodeData = _nodeData.remove(node.getUniqueId());
    if (nodeData == null) {
      // Excluded
      return;
    }
    final Set<Pair<String, ValueProperties>> nodeRequirements = nodeData.getRequirements();
    if (node.getParentNodeId() != null) {
      // Retrieve the parent portfolio node's requirements
      final NodeData parentNodeData = _nodeData.get(node.getParentNodeId());
      parentNodeData.addRequirements(nodeRequirements);
    }
    final ComputationTargetSpecification targetSpec = nodeData.getTargetSpecification();
    // Add the value requirements for the current portfolio node to the graph builder's set of value requirements,
    // building them using the requirements gathered during its children's traversal and the newly created computation
    // target spec for this portfolio node.
    for (final Pair<String, ValueProperties> requiredOutput : nodeRequirements) {
      addValueRequirement(new ValueRequirement(requiredOutput.getFirst(), targetSpec, requiredOutput.getSecond()));
    }
  }

}
