package ca.uhn.fhir.jpa.subscription.module.cache;

import ca.uhn.fhir.jpa.subscription.match.registry.ActiveSubscription;
import ca.uhn.fhir.jpa.subscription.model.DebeziumMessage;
import ca.uhn.fhir.parser.DataFormatException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.compress.compressors.gzip.GzipUtils;
import org.apache.commons.io.IOUtils;
import org.hl7.fhir.dstu3.model.Subscription;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.zip.GZIPInputStream;

import static org.junit.jupiter.api.Assertions.*;

public class SubscriptionRegistryTest extends BaseSubscriptionRegistryTest {
	@Test
	public void updateSubscriptionReusesActiveSubscription() {
		Subscription subscription = createSubscription();
		assertRegistrySize(0);
		mySubscriptionRegistry.registerSubscriptionUnlessAlreadyRegistered(subscription);
		assertRegistrySize(1);
		ActiveSubscription origActiveSubscription = mySubscriptionRegistry.get(SUBSCRIPTION_ID);
		assertEquals(ORIG_CRITERIA, origActiveSubscription.getCriteriaString());

		subscription.setCriteria(NEW_CRITERIA);
		assertEquals(ORIG_CRITERIA, origActiveSubscription.getCriteriaString());
		mySubscriptionRegistry.registerSubscriptionUnlessAlreadyRegistered(subscription);
		assertRegistrySize(1);
		ActiveSubscription newActiveSubscription = mySubscriptionRegistry.get(SUBSCRIPTION_ID);
		assertEquals(NEW_CRITERIA, newActiveSubscription.getCriteriaString());
		// The same object
		assertTrue(newActiveSubscription == origActiveSubscription);
	}

	@Test
	public void updateSubscriptionDoesntReusesActiveSubscriptionWhenChannelChanges() {
		Subscription subscription = createSubscription();
		assertRegistrySize(0);
		mySubscriptionRegistry.registerSubscriptionUnlessAlreadyRegistered(subscription);
		assertRegistrySize(1);

		ActiveSubscription origActiveSubscription = mySubscriptionRegistry.get(SUBSCRIPTION_ID);
		assertEquals(ORIG_CRITERIA, origActiveSubscription.getCriteriaString());

		setChannel(subscription, Subscription.SubscriptionChannelType.EMAIL);

		assertEquals(ORIG_CRITERIA, origActiveSubscription.getCriteriaString());
		mySubscriptionRegistry.registerSubscriptionUnlessAlreadyRegistered(subscription);
		assertRegistrySize(1);

		ActiveSubscription newActiveSubscription = mySubscriptionRegistry.get(SUBSCRIPTION_ID);
		// A new object
		assertFalse(newActiveSubscription == origActiveSubscription);
	}

	@Test
	public void testMessageDeserializes() throws IOException {
		String s = "{\n" +
			"   \"schema\":{\n" +
			"      \"type\":\"struct\",\n" +
			"      \"fields\":[\n" +
			"         {\n" +
			"            \"type\":\"struct\",\n" +
			"            \"fields\":[\n" +
			"               {\n" +
			"                  \"type\":\"int64\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"field\":\"PID\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"int32\",\n" +
			"                  \"optional\":true,\n" +
			"                  \"name\":\"io.debezium.time.Date\",\n" +
			"                  \"version\":1,\n" +
			"                  \"field\":\"PARTITION_DATE\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"int32\",\n" +
			"                  \"optional\":true,\n" +
			"                  \"field\":\"PARTITION_ID\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"int64\",\n" +
			"                  \"optional\":true,\n" +
			"                  \"name\":\"io.debezium.time.NanoTimestamp\",\n" +
			"                  \"version\":1,\n" +
			"                  \"field\":\"RES_DELETED_AT\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"string\",\n" +
			"                  \"optional\":true,\n" +
			"                  \"field\":\"RES_VERSION\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"boolean\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"field\":\"HAS_TAGS\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"int64\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"name\":\"io.debezium.time.NanoTimestamp\",\n" +
			"                  \"version\":1,\n" +
			"                  \"field\":\"RES_PUBLISHED\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"int64\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"name\":\"io.debezium.time.NanoTimestamp\",\n" +
			"                  \"version\":1,\n" +
			"                  \"field\":\"RES_UPDATED\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"string\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"field\":\"RES_ENCODING\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"bytes\",\n" +
			"                  \"optional\":true,\n" +
			"                  \"field\":\"RES_TEXT\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"int64\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"field\":\"RES_ID\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"string\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"field\":\"RES_TYPE\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"int64\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"field\":\"RES_VER\"\n" +
			"               }\n" +
			"            ],\n" +
			"            \"optional\":true,\n" +
			"            \"name\":\"mssql_events.dbo.HFJ_RES_VER.Value\",\n" +
			"            \"field\":\"before\"\n" +
			"         },\n" +
			"         {\n" +
			"            \"type\":\"struct\",\n" +
			"            \"fields\":[\n" +
			"               {\n" +
			"                  \"type\":\"int64\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"field\":\"PID\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"int32\",\n" +
			"                  \"optional\":true,\n" +
			"                  \"name\":\"io.debezium.time.Date\",\n" +
			"                  \"version\":1,\n" +
			"                  \"field\":\"PARTITION_DATE\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"int32\",\n" +
			"                  \"optional\":true,\n" +
			"                  \"field\":\"PARTITION_ID\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"int64\",\n" +
			"                  \"optional\":true,\n" +
			"                  \"name\":\"io.debezium.time.NanoTimestamp\",\n" +
			"                  \"version\":1,\n" +
			"                  \"field\":\"RES_DELETED_AT\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"string\",\n" +
			"                  \"optional\":true,\n" +
			"                  \"field\":\"RES_VERSION\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"boolean\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"field\":\"HAS_TAGS\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"int64\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"name\":\"io.debezium.time.NanoTimestamp\",\n" +
			"                  \"version\":1,\n" +
			"                  \"field\":\"RES_PUBLISHED\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"int64\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"name\":\"io.debezium.time.NanoTimestamp\",\n" +
			"                  \"version\":1,\n" +
			"                  \"field\":\"RES_UPDATED\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"string\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"field\":\"RES_ENCODING\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"bytes\",\n" +
			"                  \"optional\":true,\n" +
			"                  \"field\":\"RES_TEXT\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"int64\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"field\":\"RES_ID\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"string\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"field\":\"RES_TYPE\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"int64\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"field\":\"RES_VER\"\n" +
			"               }\n" +
			"            ],\n" +
			"            \"optional\":true,\n" +
			"            \"name\":\"mssql_events.dbo.HFJ_RES_VER.Value\",\n" +
			"            \"field\":\"after\"\n" +
			"         },\n" +
			"         {\n" +
			"            \"type\":\"struct\",\n" +
			"            \"fields\":[\n" +
			"               {\n" +
			"                  \"type\":\"string\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"field\":\"version\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"string\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"field\":\"connector\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"string\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"field\":\"name\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"int64\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"field\":\"ts_ms\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"string\",\n" +
			"                  \"optional\":true,\n" +
			"                  \"name\":\"io.debezium.data.Enum\",\n" +
			"                  \"version\":1,\n" +
			"                  \"parameters\":{\n" +
			"                     \"allowed\":\"true,last,false\"\n" +
			"                  },\n" +
			"                  \"default\":\"false\",\n" +
			"                  \"field\":\"snapshot\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"string\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"field\":\"db\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"string\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"field\":\"schema\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"string\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"field\":\"table\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"string\",\n" +
			"                  \"optional\":true,\n" +
			"                  \"field\":\"change_lsn\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"string\",\n" +
			"                  \"optional\":true,\n" +
			"                  \"field\":\"commit_lsn\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"int64\",\n" +
			"                  \"optional\":true,\n" +
			"                  \"field\":\"event_serial_no\"\n" +
			"               }\n" +
			"            ],\n" +
			"            \"optional\":false,\n" +
			"            \"name\":\"io.debezium.connector.sqlserver.Source\",\n" +
			"            \"field\":\"source\"\n" +
			"         },\n" +
			"         {\n" +
			"            \"type\":\"string\",\n" +
			"            \"optional\":false,\n" +
			"            \"field\":\"op\"\n" +
			"         },\n" +
			"         {\n" +
			"            \"type\":\"int64\",\n" +
			"            \"optional\":true,\n" +
			"            \"field\":\"ts_ms\"\n" +
			"         },\n" +
			"         {\n" +
			"            \"type\":\"struct\",\n" +
			"            \"fields\":[\n" +
			"               {\n" +
			"                  \"type\":\"string\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"field\":\"id\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"int64\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"field\":\"total_order\"\n" +
			"               },\n" +
			"               {\n" +
			"                  \"type\":\"int64\",\n" +
			"                  \"optional\":false,\n" +
			"                  \"field\":\"data_collection_order\"\n" +
			"               }\n" +
			"            ],\n" +
			"            \"optional\":true,\n" +
			"            \"field\":\"transaction\"\n" +
			"         }\n" +
			"      ],\n" +
			"      \"optional\":false,\n" +
			"      \"name\":\"mssql_events.dbo.HFJ_RES_VER.Envelope\"\n" +
			"   },\n" +
			"   \"payload\":{\n" +
			"      \"before\":\"null\",\n" +
			"      \"after\":{\n" +
			"         \"PID\":1624,\n" +
			"         \"PARTITION_DATE\":\"null\",\n" +
			"         \"PARTITION_ID\":\"null\",\n" +
			"         \"RES_DELETED_AT\":\"null\",\n" +
			"         \"RES_VERSION\":\"R4\",\n" +
			"         \"HAS_TAGS\":false,\n" +
			"         \"RES_PUBLISHED\":1598375747709000000,\n" +
			"         \"RES_UPDATED\":1598375747709000000,\n" +
			"         \"RES_ENCODING\":\"JSONC\",\n" +
			"         \"RES_TEXT\":\"H4sIAAAAAAAAAD2OTQ7CUAiEr0JYNx7AM7gw0Z1xgZSmpFpegPoT4919TavLGYZv5o0uYZOzHF9FcIsHIed+T043SXFsMJJyinoiTr1LdVoJdi2pNv4/JKAzh6sxzX7AQ7MHgijC2inDoGML1sGKa5CtnQv/+kJR9Ql3KwLPDeYyKm2QsUbkWercWHp/uc1K+HwBQO9LzMwAAAA=\",\n" +
			"         \"RES_ID\":1624,\n" +
			"         \"RES_TYPE\":\"SearchParameter\",\n" +
			"         \"RES_VER\":1\n" +
			"      },\n" +
			"      \"source\":{\n" +
			"         \"version\":\"1.2.0.Final\",\n" +
			"         \"connector\":\"sqlserver\",\n" +
			"         \"name\":\"mssql_events\",\n" +
			"         \"ts_ms\":1598376255646,\n" +
			"         \"snapshot\":\"last\",\n" +
			"         \"db\":\"cdr\",\n" +
			"         \"schema\":\"dbo\",\n" +
			"         \"table\":\"HFJ_RES_VER\",\n" +
			"         \"change_lsn\":\"None\",\n" +
			"         \"commit_lsn\":\"None\",\n" +
			"         \"event_serial_no\":\"None\"\n" +
			"      },\n" +
			"      \"op\":\"r\",\n" +
			"      \"ts_ms\":1598376255646,\n" +
			"      \"transaction\":\"None\"\n"+
			"   }\n" +
			"}";

		ObjectMapper mapper = new ObjectMapper();
		DebeziumMessage debeziumMessage = mapper.reader().readValue(s, DebeziumMessage.class);
		byte[] theResourceBytes = Base64.getDecoder().decode(debeziumMessage.getResourceBytes());
		System.out.println(decompress(theResourceBytes));
		assert debeziumMessage != null;
	}

	public static String decompress(byte[] theResource) {
		GZIPInputStream is;
		try {
			is = new GZIPInputStream(new ByteArrayInputStream(theResource));
			return IOUtils.toString(is, "UTF-8");
		} catch (IOException e) {
			throw new DataFormatException("Failed to decompress contents", e);
		}
	}

	@Test
	public void updateRemove() {
		Subscription subscription = createSubscription();
		assertRegistrySize(0);
		mySubscriptionRegistry.registerSubscriptionUnlessAlreadyRegistered(subscription);
		assertRegistrySize(1);
		mySubscriptionRegistry.unregisterSubscriptionIfRegistered(subscription.getId());
		assertRegistrySize(0);
	}

}
