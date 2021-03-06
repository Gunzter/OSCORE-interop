/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Matthias Kovatsch - creator and main architect
 ******************************************************************************/
package org.eclipse.californium.plugtests.tests;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;

import org.eclipse.californium.plugtests.PlugtestChecker.TestClientAbstract;

/**
 * TD_COAP_CORE_05: Perform GET transaction (NON mode).
 */
public class CC05 extends TestClientAbstract {

	public static final String RESOURCE_URI = "/test";
	public final ResponseCode EXPECTED_RESPONSE_CODE = ResponseCode.CONTENT;

	public CC05(String serverURI) {
		super(CC05.class.getSimpleName());

		// create the request
		Request request = Request.newGet();
		request.setConfirmable(false);
		// set the parameters and execute the request
		executeRequest(request, serverURI, RESOURCE_URI);
	}

	protected boolean checkResponse(Request request, Response response) {
		boolean success = true;

		success &= checkType(Type.NON, response.getType());
		success &= checkCode(EXPECTED_RESPONSE_CODE, response.getCode());
		success &= hasContentType(response);
		success &= hasNonEmptyPalyoad(response);

		return success;
	}
}
