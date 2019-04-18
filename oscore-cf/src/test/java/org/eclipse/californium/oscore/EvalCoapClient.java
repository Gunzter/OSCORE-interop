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

import java.util.Arrays;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.CoapEndpoint.CoapEndpointBuilder;
import org.eclipse.californium.core.network.config.NetworkConfig;

import org.eclipse.californium.cose.AlgorithmID;

/**
 * OSCORE Client for interop testing
 * 
 * Following test spec:
 * https://ericssonresearch.github.com/OSCOAP/test-spec5.html
 * 
 * Author: Rikard Höglund
 *
 */
public class EvalCoapClient {
	
	private final static String baseUri = "coap://[fd00::302:304:506:708]";

	
	public static void main(String[] args) throws OSException {
		

		//Avoid CoAP retransmissions (Should no longer be needed)
		NetworkConfig config = NetworkConfig.getStandard();
		config.setInt(NetworkConfig.Keys.MAX_RETRANSMIT, 0);
		//Set timeout to be 4 seconds
		config.setInt(NetworkConfig.Keys.ACK_TIMEOUT, 4000);
		
		
		String resourceUri = "/test/caps";
		CoapClient c = new CoapClient(baseUri + resourceUri);
		
		for(int payload_len = 5; payload_len < 125; payload_len += 5) {
			//Thread.sleep(1000);
			Request r = new Request(Code.POST);
			byte[] payload = new byte[payload_len];
			Arrays.fill(payload, (byte)0x61);
			r.setPayload(payload);
			CoapResponse resp = c.advanced(r);
			if(resp == null) {
				System.out.println("ERROR: Client application received no response!");
				return;
			}
			if( resp.getPayload().length != payload_len) {
				System.out.println("FUCKUP!" + payload_len);
			}
		}
		System.out.println("Done!");
	/*	Request r = new Request(Code.POST);
		byte[] payload = {0x61, 0x61, 0x61, 0x61}; 
		r.setPayload(payload);
		CoapResponse resp = c.advanced(r);
		
		System.out.println("Original CoAP message:");
		System.out.println("Uri-Path: " + c.getURI());
		System.out.println(Utils.prettyPrint(r));
		System.out.println("");

		if(resp == null) {
			System.out.println("ERROR: Client application received no response!");
			return;
		}
		
		System.out.println("Parsed CoAP response: ");
		System.out.println("Response code:\t" + resp.getCode());
		System.out.println("Content-Format:\t" + resp.getOptions().getContentFormat());
		System.out.println("Payload:\t" + resp.getResponseText()); */
	}

	
	/**
	 * Separate class to handle an OSCORE client instance
	 * 
	 * @author segrid-2
	 *
	 */
	public static class OscoreClient
	{
		private String uri;
		private Code method;
		
		public CoapClient c;
		
		public OscoreClient(Code method, String uri)
		{	
			OSCoreCoapStackFactory.useAsDefault();
			c = new CoapClient(uri);
			
			this.method = method;
			this.uri = uri;
		}
		
		public OscoreClient(String uri)
		{
			this(null, uri);
		}
		
		public String getURI() {
			return uri;
		}
		
		/**
		 * Send a CoapRequest via OSCORE
		 * 
		 * @return Response to CoAP request
		 */
		CoapResponse send()
		{
			OSCoreCoapStackFactory.useAsDefault();
			CoapClient c = new CoapClient(uri);

			Request r = new Request(method);
			r.getOptions().setOscore(new byte[0]);
			CoapResponse resp = c.advanced(r);
			
			return resp;
		}
		
		/**
		 * Sends an arbitrary CoAP request using OSCORE
		 * 
		 * @return Response to CoAP request
		 */
		CoapResponse advanced(Request r)
		{
			if(!r.getOptions().hasOscore()) {
				r.getOptions().setOscore(new byte[0]);
			}
			CoapResponse resp = c.advanced(r);
			
			return resp;
			
		}

	}

}
