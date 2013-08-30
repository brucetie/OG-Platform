/**
 * Copyright (C) 2013 - present by OpenGamma Inc. and the OpenGamma group of companies
 * 
 * Please see distribution for license.
 */
package com.opengamma.analytics.financial.model.option.pricing.tree;

import static org.testng.Assert.assertEquals;

import org.testng.annotations.Test;

import com.opengamma.analytics.financial.greeks.Greek;
import com.opengamma.analytics.financial.greeks.GreekResultCollection;
import com.opengamma.analytics.financial.model.volatility.BlackFormulaRepository;
import com.opengamma.analytics.financial.model.volatility.BlackScholesFormulaRepository;

/**
 * 
 */
public class EuropeanVanillaOptionFunctionProviderTest {
  private static final BinomialTreeOptionPricingModel _model = new BinomialTreeOptionPricingModel();
  private static final double SPOT = 105.;
  private static final double[] STRIKES = new double[] {81., 97., 105., 105.1, 114., 138. };
  private static final double TIME = 4.2;
  private static final double[] INTERESTS = new double[] {-0.01, 0., 0.001, 0.005, 0.01 };
  private static final double[] VOLS = new double[] {0.05, 0.1, 0.5 };

  private static final double[] DIVIDENDS = new double[] {0., 0.005, 0.02 };

  /**
   * 
   */
  @Test
  public void priceLatticeTest() {
    final LatticeSpecification[] lattices = new LatticeSpecification[] {new CoxRossRubinsteinLatticeSpecification(), new JarrowRuddLatticeSpecification(), new TrigeorgisLatticeSpecification(),
        new JabbourKraminYoungLatticeSpecification(), new TianLatticeSpecification(), new LeisenReimerLatticeSpecification() };

    final boolean[] tfSet = new boolean[] {true, false };
    for (final LatticeSpecification lattice : lattices) {
      for (final boolean isCall : tfSet) {
        for (final double strike : STRIKES) {
          for (final double interest : INTERESTS) {
            for (final double vol : VOLS) {
              final int[] choicesSteps = new int[] {31, 115, 301 };
              for (final int nSteps : choicesSteps) {
                for (final double dividend : DIVIDENDS) {
                  final OptionFunctionProvider1D function = new EuropeanVanillaOptionFunctionProvider(strike, nSteps, isCall);
                  final double exactDiv = BlackScholesFormulaRepository.price(SPOT, strike, TIME, vol, interest, interest - dividend, isCall);
                  final double resDiv = _model.getPrice(lattice, function, SPOT, TIME, vol, interest, dividend);
                  final double refDiv = (lattice instanceof LeisenReimerLatticeSpecification) ? Math.max(exactDiv, 1.) / nSteps / nSteps : Math.max(exactDiv, 1.) / Math.sqrt(nSteps);
                  //                  System.out.println(SPOT + "\t" + strike + "\t" + TIME + "\t" + vol + "\t" + interest + "\t" + dividend + "\t" + nSteps + "\t" + isCall);
                  assertEquals(resDiv, exactDiv, refDiv);
                }
              }
            }
          }
        }
      }
    }
  }

  /**
   * The dividend is cash or proportional to asset price
   */
  @Test
  public void priceDiscreteDividendTest() {
    final LatticeSpecification[] lattices = new LatticeSpecification[] {new CoxRossRubinsteinLatticeSpecification(), new JarrowRuddLatticeSpecification(), new TrigeorgisLatticeSpecification(),
        new JabbourKraminYoungLatticeSpecification(), new TianLatticeSpecification(), new LeisenReimerLatticeSpecification() };

    final double[] propDividends = new double[] {0.01, 0.01, 0.01 };
    final double[] cashDividends = new double[] {5., 10., 8. };
    final double[] dividendTimes = new double[] {TIME / 6., TIME / 3., TIME / 2. };

    final boolean[] tfSet = new boolean[] {true, false };
    for (final LatticeSpecification lattice : lattices) {
      for (final boolean isCall : tfSet) {
        for (final double strike : STRIKES) {
          for (final double interest : INTERESTS) {
            for (final double vol : VOLS) {
              final int[] choicesSteps = new int[] {31, 115, 301 };
              for (final int nSteps : choicesSteps) {
                final OptionFunctionProvider1D function = new EuropeanVanillaOptionFunctionProvider(strike, nSteps, isCall);
                final DividendFunctionProvider cashDividend = new CashDividendFunctionProvider(dividendTimes, cashDividends);
                final DividendFunctionProvider propDividend = new ProportionalDividendFunctionProvider(dividendTimes, propDividends);
                final double df = Math.exp(-interest * TIME);
                final double resSpot = SPOT * Math.exp(interest * TIME) * (1. - propDividends[0]) * (1. - propDividends[1]) * (1. - propDividends[2]);
                final double modSpot = SPOT - cashDividends[0] * Math.exp(-interest * dividendTimes[0]) - cashDividends[1] * Math.exp(-interest * dividendTimes[1]) - cashDividends[2] *
                    Math.exp(-interest * dividendTimes[2]);
                final double exactProp = df * BlackFormulaRepository.price(resSpot, strike, TIME, vol, isCall);
                final double appCash = BlackScholesFormulaRepository.price(modSpot, strike, TIME, vol, interest, interest, isCall);
                final double resProp = _model.getPrice(lattice, function, SPOT, TIME, vol, interest, propDividend);
                final double refProp = Math.max(exactProp, 1.) / Math.sqrt(nSteps);
                assertEquals(resProp, exactProp, refProp);
                final double resCash = _model.getPrice(lattice, function, SPOT, TIME, vol, interest, cashDividend);
                final double refCash = Math.max(appCash, 1.) / Math.sqrt(nSteps);
                assertEquals(resCash, appCash, refCash);
              }
            }
          }
        }
      }
    }
  }

  /**
   * 
   */
  @Test
  public void greekTest() {
    final LatticeSpecification[] lattices = new LatticeSpecification[] {new CoxRossRubinsteinLatticeSpecification(), new JarrowRuddLatticeSpecification(),
        new TrigeorgisLatticeSpecification(), new JabbourKraminYoungLatticeSpecification(), new TianLatticeSpecification() };
    final boolean[] tfSet = new boolean[] {true, false };
    for (final LatticeSpecification lattice : lattices) {
      for (final boolean isCall : tfSet) {
        for (final double strike : STRIKES) {
          for (final double interest : INTERESTS) {
            for (final double vol : VOLS) {
              final int[] choicesSteps = new int[] {31, 112, 301 };
              for (final int nSteps : choicesSteps) {
                for (final double dividend : DIVIDENDS) {
                  final OptionFunctionProvider1D function = new EuropeanVanillaOptionFunctionProvider(strike, nSteps, isCall);
                  final GreekResultCollection resDiv = _model.getGreeks(lattice, function, SPOT, TIME, vol, interest, dividend);
                  final double priceDiv = BlackScholesFormulaRepository.price(SPOT, strike, TIME, vol, interest, interest - dividend, isCall);
                  final double refPriceDiv = Math.max(Math.abs(priceDiv), 1.) / Math.sqrt(nSteps);
                  assertEquals(resDiv.get(Greek.FAIR_PRICE), priceDiv, refPriceDiv);
                  final double deltaDiv = BlackScholesFormulaRepository.delta(SPOT, strike, TIME, vol, interest, interest - dividend, isCall);
                  final double refDeltaDiv = Math.max(Math.abs(deltaDiv), 1.) / Math.sqrt(nSteps);
                  assertEquals(resDiv.get(Greek.DELTA), deltaDiv, refDeltaDiv);
                  final double gammaDiv = BlackScholesFormulaRepository.gamma(SPOT, strike, TIME, vol, interest, interest - dividend);
                  final double refGammaDiv = Math.max(Math.abs(gammaDiv), 1.) / Math.sqrt(nSteps);
                  assertEquals(resDiv.get(Greek.GAMMA), gammaDiv, refGammaDiv);
                  final double thetaDiv = BlackScholesFormulaRepository.theta(SPOT, strike, TIME, vol, interest, interest - dividend, isCall);
                  final double refThetaDiv = Math.max(Math.abs(thetaDiv), 1.) / Math.sqrt(nSteps);
                  assertEquals(resDiv.get(Greek.THETA), thetaDiv, refThetaDiv);
                }
              }
            }
          }
        }
      }
    }
  }

  /**
   * 
   */
  @Test
  public void greekLeisenReimerTest() {
    final LatticeSpecification lattice = new LeisenReimerLatticeSpecification();

    final boolean[] tfSet = new boolean[] {true, false };
    for (final boolean isCall : tfSet) {
      for (final double strike : STRIKES) {
        for (final double interest : INTERESTS) {
          for (final double vol : VOLS) {
            final int[] choicesSteps = new int[] {31, 109, 301 };
            for (final int nSteps : choicesSteps) {
              for (final double dividend : DIVIDENDS) {
                final OptionFunctionProvider1D function = new EuropeanVanillaOptionFunctionProvider(strike, nSteps, isCall);
                final GreekResultCollection resDiv = _model.getGreeks(lattice, function, SPOT, TIME, vol, interest, dividend);
                final double priceDiv = BlackScholesFormulaRepository.price(SPOT, strike, TIME, vol, interest, interest - dividend, isCall);
                final double refPriceDiv = Math.max(Math.abs(priceDiv), 1.) / nSteps;
                assertEquals(resDiv.get(Greek.FAIR_PRICE), priceDiv, refPriceDiv);
                final double deltaDiv = BlackScholesFormulaRepository.delta(SPOT, strike, TIME, vol, interest, interest - dividend, isCall);
                final double refDeltaDiv = Math.max(Math.abs(deltaDiv), 1.) / nSteps;
                assertEquals(resDiv.get(Greek.DELTA), deltaDiv, refDeltaDiv);
                final double gammaDiv = BlackScholesFormulaRepository.gamma(SPOT, strike, TIME, vol, interest, interest - dividend);
                final double refGammaDiv = Math.max(Math.abs(gammaDiv), 1.) / nSteps;
                assertEquals(resDiv.get(Greek.GAMMA), gammaDiv, refGammaDiv);
                final double thetaDiv = BlackScholesFormulaRepository.theta(SPOT, strike, TIME, vol, interest, interest - dividend, isCall);
                final double refThetaDiv = Math.max(Math.abs(thetaDiv), 1.) / nSteps;
                //                System.out.println(SPOT + "\t" + strike + "\t" + TIME + "\t" + vol + "\t" + interest + "\t" + dividend + "\t" + nSteps + "\t" + isCall);
                assertEquals(resDiv.get(Greek.THETA), thetaDiv, refThetaDiv * 10.);
              }
            }
          }
        }
      }
    }
  }

  /**
   * The dividend is cash or proportional to asset price
   */
  @Test
  public void greeksDiscreteDividendLatticeTest() {
    final LatticeSpecification[] lattices = new LatticeSpecification[] {new CoxRossRubinsteinLatticeSpecification(), new JarrowRuddLatticeSpecification(), new TrigeorgisLatticeSpecification(),
        new JabbourKraminYoungLatticeSpecification(), new TianLatticeSpecification(), new LeisenReimerLatticeSpecification() };

    final double[] propDividends = new double[] {0.01, 0.01, 0.01 };
    final double[] cashDividends = new double[] {5., 10., 8. };
    final double[] dividendTimes = new double[] {TIME / 6., TIME / 3., TIME / 2. };

    final boolean[] tfSet = new boolean[] {true, false };
    for (final LatticeSpecification lattice : lattices) {
      for (final boolean isCall : tfSet) {
        for (final double strike : STRIKES) {
          for (final double interest : INTERESTS) {
            for (final double vol : VOLS) {
              final int nSteps = 401;
              final double resSpot = SPOT * (1. - propDividends[0]) * (1. - propDividends[1]) * (1. - propDividends[2]);
              final double modSpot = SPOT - cashDividends[0] * Math.exp(-interest * dividendTimes[0]) - cashDividends[1] * Math.exp(-interest * dividendTimes[1]) - cashDividends[2] *
                  Math.exp(-interest * dividendTimes[2]);
              final double exactPriceProp = BlackScholesFormulaRepository.price(resSpot, strike, TIME, vol, interest, interest, isCall);
              final double exactDeltaProp = BlackScholesFormulaRepository.delta(resSpot, strike, TIME, vol, interest, interest, isCall);
              final double exactGammaProp = BlackScholesFormulaRepository.gamma(resSpot, strike, TIME, vol, interest, interest);
              final double exactThetaProp = BlackScholesFormulaRepository.theta(resSpot, strike, TIME, vol, interest, interest, isCall);

              final double appPriceCash = BlackScholesFormulaRepository.price(modSpot, strike, TIME, vol, interest, interest, isCall);
              final double appDeltaCash = BlackScholesFormulaRepository.delta(modSpot, strike, TIME, vol, interest, interest, isCall);
              final double appGammaCash = BlackScholesFormulaRepository.gamma(modSpot, strike, TIME, vol, interest, interest);
              final double appThetaCash = BlackScholesFormulaRepository.theta(modSpot, strike, TIME, vol, interest, interest, isCall);

              final OptionFunctionProvider1D function = new EuropeanVanillaOptionFunctionProvider(strike, nSteps, isCall);
              final DividendFunctionProvider cashDividend = new CashDividendFunctionProvider(dividendTimes, cashDividends);
              final DividendFunctionProvider propDividend = new ProportionalDividendFunctionProvider(dividendTimes, propDividends);
              final GreekResultCollection resProp = _model.getGreeks(lattice, function, SPOT, TIME, vol, interest, propDividend);
              final GreekResultCollection resCash = _model.getGreeks(lattice, function, SPOT, TIME, vol, interest, cashDividend);

              assertEquals(resProp.get(Greek.FAIR_PRICE), exactPriceProp, Math.max(1., Math.abs(exactPriceProp)) * 1.e-2);
              assertEquals(resProp.get(Greek.DELTA), exactDeltaProp, Math.max(1., Math.abs(exactDeltaProp)) * 1.e-1);
              assertEquals(resProp.get(Greek.GAMMA), exactGammaProp, Math.max(1., Math.abs(exactGammaProp)) * 1.e-1);
              assertEquals(resProp.get(Greek.THETA), exactThetaProp, Math.max(1., Math.abs(exactThetaProp)) * 1.e-1);

              assertEquals(resCash.get(Greek.FAIR_PRICE), appPriceCash, Math.max(1., Math.abs(appPriceCash)) * 1.e-2);
              assertEquals(resCash.get(Greek.DELTA), appDeltaCash, Math.max(1., Math.abs(appDeltaCash)) * 1.e-1);
              assertEquals(resCash.get(Greek.GAMMA), appGammaCash, Math.max(1., Math.abs(appGammaCash)) * 1.e-1);
              assertEquals(resCash.get(Greek.THETA), appThetaCash, Math.max(1., Math.abs(appThetaCash)));
            }
          }
        }
      }
    }
  }

  /**
   * non-constant volatility and interest rate
   */
  @Test
  public void timeVaryingVolTest() {
    final LatticeSpecification lattice1 = new TimeVaryingLatticeSpecification();
    final double[] time_set = new double[] {0.5, 1.2 };
    final int steps = 801;

    final double[] vol = new double[steps];
    final double[] rate = new double[steps];
    final double[] dividend = new double[steps];
    final double constA = 0.01;
    final double constB = 0.001;
    final double constC = 0.1;
    final double constD = 0.05;

    final boolean[] tfSet = new boolean[] {true, false };
    for (final boolean isCall : tfSet) {
      for (final double strike : STRIKES) {
        for (final double time : time_set) {
          for (int i = 0; i < steps; ++i) {
            rate[i] = constA + constB * i * time / steps;
            vol[i] = constC + constD * Math.sin(i * time / steps);
            dividend[i] = 0.005;
          }
          final double rateRef = constA + 0.5 * constB * time;
          final double volRef = Math.sqrt(constC * constC + 0.5 * constD * constD + 2. * constC * constD / time * (1. - Math.cos(time)) - constD * constD * 0.25 / time * Math.sin(2. * time));

          final OptionFunctionProvider1D functionVanilla = new EuropeanVanillaOptionFunctionProvider(strike, steps, isCall);
          final double resPrice = _model.getPrice(functionVanilla, SPOT, time, vol, rate, dividend);
          final GreekResultCollection resGreeks = _model.getGreeks(functionVanilla, SPOT, time, vol, rate, dividend);

          final double resPriceConst = _model.getPrice(lattice1, functionVanilla, SPOT, time, volRef, rateRef, dividend[0]);
          final GreekResultCollection resGreeksConst = _model.getGreeks(lattice1, functionVanilla, SPOT, time, volRef, rateRef, dividend[0]);
          assertEquals(resPrice, resPriceConst, Math.abs(resPriceConst) * 1.e-1);
          assertEquals(resGreeks.get(Greek.FAIR_PRICE), resGreeksConst.get(Greek.FAIR_PRICE), Math.max(Math.abs(resGreeksConst.get(Greek.FAIR_PRICE)), 0.1) * 0.1);
          assertEquals(resGreeks.get(Greek.DELTA), resGreeksConst.get(Greek.DELTA), Math.max(Math.abs(resGreeksConst.get(Greek.DELTA)), 0.1) * 0.1);
          assertEquals(resGreeks.get(Greek.GAMMA), resGreeksConst.get(Greek.GAMMA), Math.max(Math.abs(resGreeksConst.get(Greek.GAMMA)), 0.1) * 0.1);
          assertEquals(resGreeks.get(Greek.THETA), resGreeksConst.get(Greek.THETA), Math.max(Math.abs(resGreeksConst.get(Greek.THETA)), 0.1));
        }
      }
    }
  }
}