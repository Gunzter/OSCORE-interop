/*******************************************************************************
 * Copyright (c) 2018 RISE SICS and others.
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
 *    Tobias Andersson (RISE SICS)
 *    Rikard Höglund (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.examples.CredentialsUtil;
import org.eclipse.californium.examples.CredentialsUtil.Mode;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;

public class EvalDtlsClient {

	public static final List<Mode> SUPPORTED_MODES = Arrays
			.asList(new Mode[] { Mode.PSK, Mode.RPK, Mode.X509, Mode.RPK_TRUST, Mode.X509_TRUST });
	private static final String SERVER_URI = "coaps://[fd00::302:304:506:708]/test/caps";

	private final DTLSConnector dtlsConnector;

	public EvalDtlsClient(DTLSConnector dtlsConnector) {
		this.dtlsConnector = dtlsConnector;
	}

	public void test() {
		CoapResponse response = null;
		try {
			URI uri = new URI(SERVER_URI);
			CoapClient client = new CoapClient(uri);
			CoapEndpoint.CoapEndpointBuilder builder = new CoapEndpoint.CoapEndpointBuilder();
			builder.setConnector(dtlsConnector);
			
			client.setEndpoint(builder.build());
			Request r = new Request(Code.POST);
			byte[] payload = {0x61, 0x61, 0x61, 0x61}; 
			r.setPayload(payload);
			CoapResponse resp = client.advanced(r);
			
		
			System.out.println("Original CoAP message:");
			System.out.println("Uri-Path: " + client.getURI());
			System.out.println(Utils.prettyPrint(r));
			System.out.println("");

			if(resp == null) {
				System.out.println("ERROR: Client application received no response!");
				return;
			}
			
			System.out.println("Parsed CoAP response: ");
			System.out.println("Response code:\t" + resp.getCode());
			System.out.println("Content-Format:\t" + resp.getOptions().getContentFormat());
			System.out.println("Payload:\t" + resp.getResponseText());
			
			client.shutdown();
		
		} catch (URISyntaxException e) {
			System.err.println("Invalid URI: " + e.getMessage());
			System.exit(-1);
		}

	}

	public static void main(String[] args) throws InterruptedException {

		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
		builder.setClientOnly();
		builder.setSniEnabled(false);
		List<Mode> modes = CredentialsUtil.parse(args, CredentialsUtil.DEFAULT_MODES, SUPPORTED_MODES);

		//builder.setPskStore(new StaticPskStore(CredentialsUtil.PSK_IDENTITY, CredentialsUtil.PSK_SECRET));
		builder.setPskStore(new StaticPskStore("user", "password".getBytes()));
		System.out.println("PSK ID " + "user" + " PSK-secret " + "password".getBytes());
		//byte[] arr = "password".getBytes();
		//for(int i = 0; i < arr.length; i++) {
//			System.out.println(arr[i]&0xFF);
//		}
		CredentialsUtil.setupCredentials(builder, CredentialsUtil.CLIENT_NAME, modes);
		DTLSConnector dtlsConnector = new DTLSConnector(builder.build());

		EvalDtlsClient client = new EvalDtlsClient(dtlsConnector);
		client.test();
	}
}

