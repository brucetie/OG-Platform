/**
 * Copyright (C) 2012 - present by OpenGamma Inc. and the OpenGamma group of companies
 *
 * Please see distribution for license.
 */
package com.opengamma.integration.loadsave.portfolio.web;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.StreamingOutput;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.opengamma.bbg.ReferenceDataProvider;
import com.opengamma.core.historicaltimeseries.HistoricalTimeSeriesSource;
import com.opengamma.integration.loadsave.portfolio.ResolvingPortfolioCopier;
import com.opengamma.master.historicaltimeseries.HistoricalTimeSeriesMaster;
import com.opengamma.util.ArgumentChecker;
import com.sun.jersey.multipart.BodyPartEntity;
import com.sun.jersey.multipart.FormDataBodyPart;
import com.sun.jersey.multipart.FormDataMultiPart;

/**
 * REST resource that uploads a CSV file containing a portfolio definition and passes it to a portfolio loader.
 * TODO currently it doesn't do anything except read the file and send back some made-up data to the client
 */
@Path("portfolioupload")
public class PortfolioLoaderResource {

  private static final Logger s_logger = LoggerFactory.getLogger(PortfolioLoaderResource.class);
  private final HistoricalTimeSeriesMaster _historicalTimeSeriesMaster;
  private final HistoricalTimeSeriesSource _bloombergHistoricalTimeSeriesSource;
  private final ReferenceDataProvider _bloombergReferenceDataProvider;

  public PortfolioLoaderResource(HistoricalTimeSeriesMaster historicalTimeSeriesMaster,
                                 HistoricalTimeSeriesSource bloombergHistoricalTimeSeriesSource,
                                 ReferenceDataProvider bloombergReferenceDataProvider) {
    ArgumentChecker.notNull(historicalTimeSeriesMaster, "historicalTimeSeriesMaster");
    ArgumentChecker.notNull(bloombergHistoricalTimeSeriesSource, "bloombergHistoricalTimeSeriesSource");
    ArgumentChecker.notNull(bloombergReferenceDataProvider, "bloombergReferenceDataProvider");
    _historicalTimeSeriesMaster = historicalTimeSeriesMaster;
    _bloombergHistoricalTimeSeriesSource = bloombergHistoricalTimeSeriesSource;
    _bloombergReferenceDataProvider = bloombergReferenceDataProvider;
  }

  @Path("{updatePeriod}/{updateCount}")
  @POST
  @Consumes(MediaType.MULTIPART_FORM_DATA)
  @Produces(MediaType.TEXT_PLAIN)
  public Response uploadPortfolio(FormDataMultiPart formData,
                                  // TODO according to the docs this should work but jersey won't start with them uncommented
                                  //@FormDataParam("file") FormDataBodyPart fileBodyPart,
                                  //@FormDataParam("portfolioName") String portfolioName,
                                  //@FormDataParam("dataField") String dataField,
                                  @PathParam("updatePeriod") final long updatePeriod,
                                  @PathParam("updateCount") final int updateCount) throws IOException {
    FormDataBodyPart fileBodyPart = getBodyPart(formData, "file");
    FormDataBodyPart dataFieldBodyPart = getBodyPart(formData, "dataField");
    FormDataBodyPart bodyPart = getBodyPart(formData, "portfolioName");
    String dataField = dataFieldBodyPart.getValue();
    // TODO real values
    String dataProvider = null;
    String[] dataFields = null;
    String portfolioName = bodyPart.getValue();
    String fileName = fileBodyPart.getFormDataContentDisposition().getFileName();
    Object fileEntity = fileBodyPart.getEntity();
    if (!(fileEntity instanceof BodyPartEntity)) {
      throw new WebApplicationException(Response.Status.BAD_REQUEST);
    }
    InputStream fileStream = ((BodyPartEntity) fileEntity).getInputStream();
    String fileContent = IOUtils.toString(fileStream);
    s_logger.warn("Portfolio uploaded. fileName: {}, portfolioName: {}, dataField: {}, portfolio: {}",
                  new Object[]{fileName, portfolioName, dataField, fileContent});
    // TODO fix the args
    // TODO stream the output back to the web
    //_copier.loadPortfolio(portfolioName, fileName, fileStream, "", "", new String[]{dataField}, "", true);
    ResolvingPortfolioCopier copier = new ResolvingPortfolioCopier(_historicalTimeSeriesMaster,
                                                                   _bloombergHistoricalTimeSeriesSource,
                                                                   _bloombergReferenceDataProvider,
                                                                   dataProvider,
                                                                   dataFields);

    copier.copy();
    StreamingOutput streamingOutput = new StreamingOutput() {
      @Override
      public void write(OutputStream output) throws IOException, WebApplicationException {
        for (int i = 0; i < updateCount; i++) {
          try {
            Thread.sleep(updatePeriod);
          } catch (InterruptedException e) {
            s_logger.warn("This shouldn't happen");
          }
          output.write("uploading portfolio...".getBytes());
          output.flush();
        }
      }
    };
    return Response.ok(streamingOutput).build();
  }

  private static FormDataBodyPart getBodyPart(FormDataMultiPart formData, String fieldName) {
    FormDataBodyPart bodyPart = formData.getField(fieldName);
    if (bodyPart == null) {
      throw new WebApplicationException(Response.Status.BAD_REQUEST);
    }
    return bodyPart;
  }
}
