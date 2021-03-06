/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add tests to start and stop 
 *                                                    the DTLSConnector
 ******************************************************************************/
package org.eclipse.californium.scandium;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.SimpleMessageCallback;
import org.eclipse.californium.scandium.ConnectorHelper.LatchDecrementingRawDataChannel;
import org.eclipse.californium.scandium.category.Medium;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.InMemoryClientSessionCache;
import org.eclipse.californium.scandium.dtls.InMemoryConnectionStore;
import org.eclipse.californium.scandium.rule.DtlsNetworkRule;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies behavior of {@link DTLSConnector}.
 * <p>
 * Focus on start and stop the DTLSConnector. Currently it only tests the stop,
 * if the DTLS session is successful established.
 */
@Category(Medium.class)
public class DTLSConnectorStartStopTest {

	public static final Logger LOGGER = LoggerFactory.getLogger(DTLSConnectorStartStopTest.class.getName());

	@ClassRule
	public static DtlsNetworkRule network = new DtlsNetworkRule(DtlsNetworkRule.Mode.DIRECT,
			DtlsNetworkRule.Mode.NATIVE);

	@Rule
	public TestNameLoggerRule names = new TestNameLoggerRule();

	private static final int CLIENT_CONNECTION_STORE_CAPACITY = 5;

	static ConnectorHelper serverHelper;
	static InMemoryClientSessionCache clientSessionCache;

	DTLSConnector client;
	DtlsConnectorConfig clientConfig;
	LatchDecrementingRawDataChannel clientChannel;
	InMemoryConnectionStore clientConnectionStore;

	/**
	 * Configures and starts a server side connector for running the tests
	 * against.
	 * 
	 * @throws IOException if the key store to read the server's keys from
	 *             cannot be found.
	 * @throws GeneralSecurityException if the server's keys cannot be read.
	 */
	@BeforeClass
	public static void startServer() throws IOException, GeneralSecurityException {
		serverHelper = new ConnectorHelper();
		serverHelper.startServer();
		clientSessionCache = new InMemoryClientSessionCache();
	}

	/**
	 * Shuts down and destroys the sever side connector.
	 */
	@AfterClass
	public static void tearDown() {
		serverHelper.destroyServer();
	}

	@Before
	public void setUp() throws IOException, GeneralSecurityException {
		clientConnectionStore = new InMemoryConnectionStore(CLIENT_CONNECTION_STORE_CAPACITY, 60, clientSessionCache);
		clientConnectionStore.setTag("client");
		InetSocketAddress clientEndpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
		clientConfig = ConnectorHelper.newStandardClientConfig(clientEndpoint);
		client = new DTLSConnector(clientConfig, clientConnectionStore);
		clientChannel = serverHelper.new LatchDecrementingRawDataChannel();
		client.setRawDataReceiver(clientChannel);
	}

	@After
	public void cleanUp() {
		if (client != null) {
			client.destroy();
		}
		serverHelper.cleanUpServer();
	}

	@Test
	public void testStopCallsMessageCallbackOnError()
			throws InterruptedException, IOException, GeneralSecurityException {
		testStopCallsMessageCallbackOnError(100, 20, false);
	}

	@Test
	public void testStopCallsMessageCallbackOnErrorCirtical()
			throws InterruptedException, IOException, GeneralSecurityException {
		testStopCallsMessageCallbackOnError(2, 20, false);
	}

	@Test
	public void testRestartFromClientSessionCache() throws InterruptedException, IOException, GeneralSecurityException {
		testStopCallsMessageCallbackOnError(10, 20, true);
	}

	private void testStopCallsMessageCallbackOnError(final int pending, final int loops, boolean restart)
			throws InterruptedException, IOException, GeneralSecurityException {
		byte[] data = { 0, 1, 2 };
		int lastServerRemaining = -1;
		InetSocketAddress dest = serverHelper.serverEndpoint;
		EndpointContext context = new AddressEndpointContext(dest);
		boolean setup = false;

		for (int loop = 0; loop < loops; ++loop) {
			if (setup) {
				setUp();
			}
			try {
				client.start();
			} catch (IOException e) {
			}
			Thread.sleep(100);
			clientConnectionStore.dump();
			serverHelper.serverConnectionStore.dump();
			LOGGER.info("start/stop: {}/{} loops, {} msgs server {}, client {}", loop, loops, pending, dest,
					client.getAddress());

			List<SimpleMessageCallback> callbacks = new ArrayList<>();

			CountDownLatch latch = new CountDownLatch(1);
			clientChannel.setLatch(latch);

			SimpleMessageCallback callback = new SimpleMessageCallback(pending, false);
			SimpleMessageCallback messageCallback = new SimpleMessageCallback(0, true, callback);
			callbacks.add(messageCallback);
			RawData message = RawData.outbound(data, context, messageCallback, false);
			client.send(message);
			assertTrue(
					"loop: " + loop + ", " + pending + " msgs, DTLS handshake timed out after "
							+ ConnectorHelper.MAX_TIME_TO_WAIT_SECS + " seconds",
					latch.await(ConnectorHelper.MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			if (lastServerRemaining > -1) {
				assertThat("number of server sessions changed!", serverHelper.serverConnectionStore.remainingCapacity(),
						is(lastServerRemaining));
			}

			for (int index = 1; index < pending; ++index) {
				LOGGER.info("loop: {}, send {}", loop, index);
				messageCallback = new SimpleMessageCallback(0, true, callback);
				callbacks.add(messageCallback);
				message = RawData.outbound(data, context, messageCallback, false);
				client.send(message);
			}

			client.stop();
			boolean complete = callback.await(200);
			if (!complete) {
				LOGGER.info("loop: {}, still miss {} calls!", loop, callback.getPendingCalls());
				for (int index = 0; index < callbacks.size(); ++index) {
					SimpleMessageCallback calls = callbacks.get(index);
					if (!calls.isSent() && calls.getError() == null) {
						LOGGER.info("loop: {}, call {} {}", loop, index, calls);
					}
				}
			}
			assertThat("loop: " + loop + ", " + callback.toString(), complete, is(true));
			lastServerRemaining = serverHelper.serverConnectionStore.remainingCapacity();
			if (restart) {
				client.destroy();
				setup = true;
			}
			assertThat("loop: " + loop + ", " + callback.toString(), callback.await(200), is(true));
			Thread.sleep(100);
		}
		Thread.sleep(100);
	}
}
