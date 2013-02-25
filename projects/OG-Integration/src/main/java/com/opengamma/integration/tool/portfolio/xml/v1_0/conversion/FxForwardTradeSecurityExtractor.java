/**
 * Copyright (C) 2013 - present by OpenGamma Inc. and the OpenGamma group of companies
 *
 * Please see distribution for license.
 */
package com.opengamma.integration.tool.portfolio.xml.v1_0.conversion;

import org.apache.commons.lang.builder.HashCodeBuilder;
import org.threeten.bp.ZonedDateTime;

import com.opengamma.OpenGammaRuntimeException;
import com.opengamma.financial.security.fx.FXForwardSecurity;
import com.opengamma.financial.security.fx.NonDeliverableFXForwardSecurity;
import com.opengamma.id.ExternalId;
import com.opengamma.integration.tool.portfolio.xml.v1_0.jaxb.FxForwardTrade;
import com.opengamma.master.security.ManageableSecurity;
import com.opengamma.util.money.Currency;

public class FxForwardTradeSecurityExtractor extends TradeSecurityExtractor<FxForwardTrade> {

  @Override
  public ManageableSecurity[] extractSecurity(FxForwardTrade trade) {

    ExternalId region = extractRegion(trade.getPaymentCalendars());
    boolean nonDeliverable = checkNonDeliverable(trade);

    Currency payCurrency = Currency.of(trade.getPayCurrency());
    double payAmount = trade.getPayAmount().doubleValue();
    Currency receiveCurrency = Currency.of(trade.getReceiveCurrency());
    double receiveAmount = trade.getReceiveAmount().doubleValue();
    ZonedDateTime forwardDate = convertLocalDate(trade.getMaturityDate());

    ManageableSecurity security = nonDeliverable ?
        // todo - expiry should be used in construction of NonDeliverableFXForwardSecurity
        new NonDeliverableFXForwardSecurity(payCurrency, payAmount, receiveCurrency, receiveAmount, forwardDate,
                                            region, trade.getSettlementCurrency().equals(trade.getReceiveCurrency())) :
        new FXForwardSecurity(payCurrency, payAmount, receiveCurrency, receiveAmount, forwardDate, region);

    security.addExternalId(ExternalId.of("XML_LOADER", Integer.toHexString(
        new HashCodeBuilder()
            .append(security.getClass())
            .append(payCurrency)
            .append(trade.getPayAmount())
            .append(trade.getReceiveCurrency())
            .append(trade.getReceiveAmount())
            .append(trade.getMaturityDate())
            .append(region).toHashCode()
    )));
    return securityArray(security);
  }

  private boolean checkNonDeliverable(FxForwardTrade trade) {

    if (trade.getSettlementCurrency() != null && trade.getFxExpiry() != null) {
      return true;
    } else if (trade.getSettlementCurrency() == null && trade.getFxExpiry() == null) {
      return false;
    } else {
      throw new OpenGammaRuntimeException(
          "Either both settlementCurrency and fxExpiry elements must be present, or neither");
    }
  }
}
