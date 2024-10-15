package ca.uhn.fhir.util;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.context.RuntimeResourceDefinition;
import org.apache.commons.lang3.StringUtils;
import org.hl7.fhir.instance.model.api.IBase;
import org.hl7.fhir.instance.model.api.IBaseBackboneElement;
import org.hl7.fhir.r4.model.Address;
import org.hl7.fhir.r4.model.BooleanType;
import org.hl7.fhir.r4.model.Claim;
import org.hl7.fhir.r4.model.Condition;
import org.hl7.fhir.r4.model.DateTimeType;
import org.hl7.fhir.r4.model.DateType;
import org.hl7.fhir.r4.model.Enumeration;
import org.hl7.fhir.r4.model.Enumerations;
import org.hl7.fhir.r4.model.Extension;
import org.hl7.fhir.r4.model.HumanName;
import org.hl7.fhir.r4.model.Identifier;
import org.hl7.fhir.r4.model.Observation;
import org.hl7.fhir.r4.model.Organization;
import org.hl7.fhir.r4.model.Patient;
import org.hl7.fhir.r4.model.Practitioner;
import org.hl7.fhir.r4.model.PrimitiveType;
import org.hl7.fhir.r4.model.Reference;
import org.hl7.fhir.r4.model.StringType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TerserUtilTest {

	private FhirContext ourFhirContext = FhirContext.forR4();
	private static final String SAMPLE_PERSON =
		 """
			  {
			        "resourceType": "Patient",
			        "extension": [
			          {
			            "url": "http://hl7.org/fhir/us/core/StructureDefinition/us-core-race",
			            "valueCoding": {
			              "system": "MyInternalRace",
			              "code": "X",
			              "display": "Eks"
			            }
			          },
			          {
			            "url": "http://hl7.org/fhir/us/core/StructureDefinition/us-core-ethnicity'",
			            "valueCoding": {
			              "system": "MyInternalEthnicity",
			              "display": "NNN"
			            }
			          }
			        ],
			        "identifier": [
			          {
			            "system": "http://example.org/member_id",
			            "value": "123123"
			          },
			          {
			            "system": "http://example.org/medicaid_id",
			            "value": "12312323123Z"
			          },
			          {
			            "system": "http://example.org/CDNS_id",
			            "value": "123123123E"
			          },
			          {
			            "system": "http://example.org/SSN"
			          }
			        ],
			        "active": true,
			        "name": [
			          {
			            "family": "TestFamily",
			            "given": [
			              "Given"
			            ]
			          }
			        ],
			        "telecom": [
			          {
			            "system": "email",
			            "value": "email@email.io"
			          },
			          {
			            "system": "phone",
			            "value": "123123231"
			          },
			          {
			            "system": "phone",
			            "value": "1231232312"
			          },
			          {
			            "system": "phone",
			            "value": "1231232314"
			          }
			        ],
			        "gender": "male",
			        "birthDate": "1900-01-01",
			        "deceasedBoolean": true,
			         "contained": [
			                {
			                    "id": "1",
			                    "identifier": [
			                        {
			                            "system": "urn:hssc:srhs:contact:organizationId",
			                            "value": "1000"
			                        }
			                    ],
			                    "name": "BUILDERS FIRST SOURCE",
			                    "resourceType": "Organization"
			                }
			            ]
			      }
			  	""";
	public static final String DATA_ABSENT_REASON_EXTENSION_URI = "http://hl7.org/fhir/StructureDefinition/data-absent-reason";

	@Test
	void cloneIdentifierIntoResource() {
		Identifier identifier = new Identifier().setSystem("http://org.com/sys").setValue("123");

		Patient p1 = new Patient();
		p1.addIdentifier(identifier);

		Patient p2 = new Patient();
		RuntimeResourceDefinition definition = ourFhirContext.getResourceDefinition(p1);
		TerserUtil.cloneIdentifierIntoResource(ourFhirContext, definition.getChildByName("identifier"), identifier, p2);

		assertThat(p2.getIdentifier()).hasSize(1);
		assertEquals(p1.getIdentifier().get(0).getSystem(), p2.getIdentifier().get(0).getSystem());
		assertEquals(p1.getIdentifier().get(0).getValue(), p2.getIdentifier().get(0).getValue());
	}

	@Test
	void cloneIdentifierIntoResourceNoDuplicates() {
		Identifier identifier = new Identifier().setSystem("http://org.com/sys").setValue("123");

		Patient p1 = new Patient();
		p1.addIdentifier(identifier);

		Patient p2 = new Patient();
		Identifier dupIdentifier = new Identifier().setSystem("http://org.com/sys").setValue("123");
		p2.addIdentifier(dupIdentifier);
		RuntimeResourceDefinition definition = ourFhirContext.getResourceDefinition(p1);
		TerserUtil.cloneIdentifierIntoResource(ourFhirContext, definition.getChildByName("identifier"), identifier, p2);

		assertThat(p2.getIdentifier()).hasSize(1);
		assertEquals(p1.getIdentifier().get(0).getSystem(), p2.getIdentifier().get(0).getSystem());
		assertEquals(p1.getIdentifier().get(0).getValue(), p2.getIdentifier().get(0).getValue());
	}

	@Test
	void testReplaceBooleanField() {
		Patient p1 = ourFhirContext.newJsonParser().parseResource(Patient.class, SAMPLE_PERSON);

		Patient p2 = new Patient();
		TerserUtil.replaceFields(ourFhirContext, p1, p2, TerserUtil.EXCLUDE_IDS_AND_META);

		assertTrue(p2.hasDeceased());
		assertTrue(((BooleanType)p2.getDeceased()).booleanValue());
		assertThat(p2.getExtension()).hasSize(2);
	}

	@Test
	void testMergeBooleanField() {
		Patient p1 = ourFhirContext.newJsonParser().parseResource(Patient.class, SAMPLE_PERSON);

		Patient p2 = new Patient();
		TerserUtil.mergeAllFields(ourFhirContext, p1, p2);

		assertTrue(p2.hasDeceased());
		assertEquals("true", p2.getDeceased().primitiveValue());
		assertThat(p2.getExtension()).hasSize(2);
	}

	@Test
	void testCloneContainedResource() {
		Patient p1 = ourFhirContext.newJsonParser().parseResource(Patient.class, SAMPLE_PERSON);

		Patient p2 = new Patient();
		TerserUtil.mergeAllFields(ourFhirContext, p1, p2);

		Organization org1 = (Organization) p1.getContained().get(0);
		Organization org2 = (Organization) p2.getContained().get(0);
		assertThat(org2).isNotEqualTo(org1);
		assertEquals("BUILDERS FIRST SOURCE", org1.getName());
		assertEquals("BUILDERS FIRST SOURCE", org2.getName());
	}

	@Test
	void cloneIdentifierIntoResourceViaHelper() {
		TerserUtilHelper p1Helper = TerserUtilHelper.newHelper(ourFhirContext, "Patient");
		p1Helper.setField("identifier.system", "http://org.com/sys");
		p1Helper.setField("identifier.value", "123");

		Patient p1 = p1Helper.getResource();
		assertThat(p1.getIdentifier()).hasSize(1);

		TerserUtilHelper p2Helper = TerserUtilHelper.newHelper(ourFhirContext, "Patient");
		RuntimeResourceDefinition definition = p1Helper.getResourceDefinition();

		TerserUtil.cloneIdentifierIntoResource(ourFhirContext, definition.getChildByName("identifier"),
			 p1.getIdentifier().get(0), p2Helper.getResource());

		assertThat(p2Helper.getFieldValues("identifier")).hasSize(1);

		Identifier id1 = (Identifier) p1Helper.getFieldValues("identifier").get(0);
		Identifier id2 = (Identifier) p2Helper.getFieldValue("identifier");
		assertTrue(id1.equalsDeep(id2));
		assertFalse(id1.equals(id2));

		assertNull(p2Helper.getFieldValue("address"));
	}

	@Test
	void testSetFieldsViaHelper() {
		TerserUtilHelper p1Helper = TerserUtilHelper.newHelper(ourFhirContext, "Patient");
		p1Helper.setField("active", "boolean", "true");
		p1Helper.setField("birthDate", "date", "1999-01-01");
		p1Helper.setField("gender", "code", "male");

		Patient p = p1Helper.getResource();
		assertTrue(p.getActive());
		assertEquals(Enumerations.AdministrativeGender.MALE, p.getGender());

		DateType check = TerserUtil.newElement(ourFhirContext, "date", "1999-01-01");
		assertEquals(check.getValue(), p.getBirthDate());
	}


	@Test
	void testFieldExists() {
		assertTrue(TerserUtil.fieldExists(ourFhirContext, "identifier", TerserUtil.newResource(ourFhirContext, "Patient")));
		assertFalse(TerserUtil.fieldExists(ourFhirContext, "randomFieldName", TerserUtil.newResource(ourFhirContext, "Patient")));
	}

	@Test
	void testCloneFields() {
		Patient p1 = new Patient();
		p1.addName().addGiven("Sigizmund");

		Patient p2 = new Patient();

		TerserUtil.mergeFieldsExceptIdAndMeta(ourFhirContext, p1, p2);

		assertThat(p2.getIdentifier()).isEmpty();

		assertNull(p2.getId());
		assertThat(p2.getName()).hasSize(1);
		assertEquals(p1.getName().get(0).getNameAsSingleString(), p2.getName().get(0).getNameAsSingleString());
	}

	@Test
	void testCloneIdentifiers() {
		Patient p1 = new Patient();
		p1.addIdentifier(new Identifier().setSystem("uri:mi").setValue("123456"));
		p1.addIdentifier(new Identifier().setSystem("uri:mdi").setValue("287351247K"));
		p1.addIdentifier(new Identifier().setSystem("uri:cdns").setValue("654841918"));
		p1.addIdentifier(new Identifier().setSystem("uri:ssn").setValue("855191882"));
		p1.addName().setFamily("Sat").addGiven("Joe");

		Patient p2 = new Patient();
		TerserUtil.mergeField(ourFhirContext, ourFhirContext.newTerser(), "identifier", p1, p2);

		assertThat(p2.getIdentifier()).hasSize(4);
		assertThat(p2.getName()).isEmpty();
	}

	@Test
	void testReplaceIdentifiers() {
		Patient p1 = new Patient();
		p1.addIdentifier(new Identifier().setSystem("uri:mi").setValue("123456"));
		p1.addIdentifier(new Identifier().setSystem("uri:mdi").setValue("287351247K"));
		p1.addIdentifier(new Identifier().setSystem("uri:cdns").setValue("654841918"));
		p1.addIdentifier(new Identifier().setSystem("uri:ssn").setValue("855191882"));
		p1.addName().setFamily("Sat").addGiven("Joe");

		Patient p2 = new Patient();
		TerserUtil.replaceField(ourFhirContext, "identifier", p1, p2);

		assertThat(p2.getIdentifier()).hasSize(4);
		assertThat(p2.getName()).isEmpty();
	}

	@Test
	void testCloneWithNonPrimitves() {
		Patient p1 = new Patient();
		Patient p2 = new Patient();

		p1.addName().addGiven("Joe");
		p1.getNameFirstRep().addGiven("George");
		assertThat(p1.getName()).hasSize(1);
		assertThat(p1.getName().get(0).getGiven()).hasSize(2);

		p2.addName().addGiven("Jeff");
		p2.getNameFirstRep().addGiven("George");
		assertThat(p2.getName()).hasSize(1);
		assertThat(p2.getName().get(0).getGiven()).hasSize(2);

		TerserUtil.mergeAllFields(ourFhirContext, p1, p2);
		assertThat(p2.getName()).hasSize(2);
		assertThat(p2.getName().get(0).getGiven()).hasSize(2);
		assertThat(p2.getName().get(1).getGiven()).hasSize(2);
	}

	@Test
	void testMergeForAddressWithExtensions() {
		Extension ext = new Extension();
		ext.setUrl("http://hapifhir.io/extensions/address#create-timestamp");
		ext.setValue(new DateTimeType("2021-01-02T11:13:15"));

		Patient p1 = new Patient();
		p1.addAddress()
			 .addLine("10 Main Street")
			 .setCity("Hamilton")
			 .setState("ON")
			 .setPostalCode("Z0Z0Z0")
			 .setCountry("Canada")
			 .addExtension(ext);

		Patient p2 = new Patient();
		p2.addAddress().addLine("10 Lenin Street").setCity("Severodvinsk").setCountry("Russia");

		TerserUtil.mergeField(ourFhirContext, "address", p1, p2);

		assertThat(p2.getAddress()).hasSize(2);
		assertEquals("[10 Lenin Street]", p2.getAddress().get(0).getLine().toString());
		assertEquals("[10 Main Street]", p2.getAddress().get(1).getLine().toString());
		assertTrue(p2.getAddress().get(1).hasExtension());

		p1 = new Patient();
		p1.addAddress().addLine("10 Main Street").addExtension(ext);
		p2 = new Patient();
		p2.addAddress().addLine("10 Main Street").addExtension(new Extension("demo", new DateTimeType("2021-01-02")));

		TerserUtil.mergeField(ourFhirContext, "address", p1, p2);
		assertThat(p2.getAddress()).hasSize(2);
		assertTrue(p2.getAddress().get(0).hasExtension());
		assertTrue(p2.getAddress().get(1).hasExtension());

	}

	@Test
	void testReplaceForAddressWithExtensions() {
		Extension ext = new Extension();
		ext.setUrl("http://hapifhir.io/extensions/address#create-timestamp");
		ext.setValue(new DateTimeType("2021-01-02T11:13:15"));

		Patient p1 = new Patient();
		p1.addAddress()
			 .addLine("10 Main Street")
			 .setCity("Hamilton")
			 .setState("ON")
			 .setPostalCode("Z0Z0Z0")
			 .setCountry("Canada")
			 .addExtension(ext);

		Patient p2 = new Patient();
		p2.addAddress().addLine("10 Lenin Street").setCity("Severodvinsk").setCountry("Russia");

		TerserUtil.replaceField(ourFhirContext, "address", p1, p2);

		assertThat(p2.getAddress()).hasSize(1);
		assertEquals("[10 Main Street]", p2.getAddress().get(0).getLine().toString());
		assertTrue(p2.getAddress().get(0).hasExtension());
	}

	@Test
	void testMergeForSimilarAddresses() {
		Extension ext = new Extension();
		ext.setUrl("http://hapifhir.io/extensions/address#create-timestamp");
		ext.setValue(new DateTimeType("2021-01-02T11:13:15"));

		Patient p1 = new Patient();
		p1.addAddress()
			 .addLine("10 Main Street")
			 .setCity("Hamilton")
			 .setState("ON")
			 .setPostalCode("Z0Z0Z0")
			 .setCountry("Canada")
			 .addExtension(ext);

		Patient p2 = new Patient();
		p2.addAddress()
			 .addLine("10 Main Street")
			 .setCity("Hamilton")
			 .setState("ON")
			 .setPostalCode("Z0Z0Z1")
			 .setCountry("Canada")
			 .addExtension(ext);

		TerserUtil.mergeField(ourFhirContext, "address", p1, p2);

		assertThat(p2.getAddress()).hasSize(2);
		assertEquals("[10 Main Street]", p2.getAddress().get(0).getLine().toString());
		assertEquals("[10 Main Street]", p2.getAddress().get(1).getLine().toString());
		assertTrue(p2.getAddress().get(1).hasExtension());
	}

	@Test
	public void testMergeWithReference() {
		Practitioner practitioner = new Practitioner();
		practitioner.setId(UUID.randomUUID().toString());
		practitioner.addName().setFamily("Smith").addGiven("Jane");

		Condition c1 = new Condition();
		c1.setRecorder(new Reference(practitioner));

		Condition c2 = new Condition();

		TerserUtil.mergeField(ourFhirContext, "recorder", c1, c2);

		assertThat(c2.getRecorder().getResource()).isSameAs(practitioner);
	}

	@ParameterizedTest
	@MethodSource("singleCardinalityArguments")
	public void testMergeWithDataAbsentReason_singleCardinality(
		 Enumeration<Observation.ObservationStatus> theFromStatus,
		 Enumeration<Observation.ObservationStatus> theToStatus,
		 Enumeration<Observation.ObservationStatus> theExpectedStatus) {
		Observation fromObservation = new Observation();
		fromObservation.setStatusElement(theFromStatus);

		Observation toObservation = new Observation();
		toObservation.setStatusElement(theToStatus);

		TerserUtil.mergeField(ourFhirContext, "status", fromObservation, toObservation);

		if (theExpectedStatus == null) {
			assertThat(toObservation.hasStatus()).isFalse();
		} else {
			assertThat(toObservation.getStatusElement().getCode()).isEqualTo(theExpectedStatus.getCode());
		}
	}

	private static Stream<Arguments> singleCardinalityArguments() {
		return Stream.of(
			 Arguments.of(null, null, null),
			 Arguments.of(statusFromEnum(Observation.ObservationStatus.FINAL), null, statusFromEnum(Observation.ObservationStatus.FINAL)),
			 Arguments.of(null, statusFromEnum(Observation.ObservationStatus.FINAL), statusFromEnum(Observation.ObservationStatus.FINAL)),
			 Arguments.of(statusFromEnum(Observation.ObservationStatus.FINAL), statusFromEnum(Observation.ObservationStatus.PRELIMINARY), statusFromEnum(Observation.ObservationStatus.FINAL)),
			 Arguments.of(statusWithDataAbsentReason(), null, statusWithDataAbsentReason()),
			 Arguments.of(null, statusWithDataAbsentReason(), statusWithDataAbsentReason()),
			 Arguments.of(statusWithDataAbsentReason(), statusWithDataAbsentReason(), statusWithDataAbsentReason()),
			 Arguments.of(statusFromEnum(Observation.ObservationStatus.FINAL), statusWithDataAbsentReason(), statusFromEnum(Observation.ObservationStatus.FINAL)),
			 Arguments.of(statusWithDataAbsentReason(), statusFromEnum(Observation.ObservationStatus.FINAL), statusFromEnum(Observation.ObservationStatus.FINAL))
		);
	}

	private static Enumeration<Observation.ObservationStatus> statusFromEnum(Observation.ObservationStatus theStatus) {
		return new Enumeration<>(new Observation.ObservationStatusEnumFactory(), theStatus);
	}

	private static Enumeration<Observation.ObservationStatus> statusWithDataAbsentReason() {
		Enumeration<Observation.ObservationStatus> enumeration = new Enumeration<>(new Observation.ObservationStatusEnumFactory());
		Enumeration<Enumerations.DataAbsentReason> extension = new Enumeration<>(new Enumerations.DataAbsentReasonEnumFactory(), Enumerations.DataAbsentReason.UNKNOWN);
		enumeration.addExtension(DATA_ABSENT_REASON_EXTENSION_URI, extension);
		return enumeration;
	}

	@ParameterizedTest
	@MethodSource("multipleCardinalityArguments")
	public void testMergeWithDataAbsentReason_multipleCardinality(
		 List<Identifier> theFromIdentifiers, List<Identifier> theToIdentifiers, List<Identifier> theExpectedIdentifiers) {
		Observation fromObservation = new Observation();
		theFromIdentifiers.forEach(fromObservation::addIdentifier);

		Observation toObservation = new Observation();
		theToIdentifiers.forEach(toObservation::addIdentifier);

		TerserUtil.mergeField(ourFhirContext, "identifier", fromObservation, toObservation);

		assertThat(toObservation.getIdentifier()).hasSize(theExpectedIdentifiers.size());
		assertThat(toObservation.getIdentifier()).allMatch(t -> {
			if (t.hasValue()) {
				return theExpectedIdentifiers.stream().anyMatch(s -> StringUtils.equals(t.getValue(), s.getValue()));
			} else if (t.hasExtension(DATA_ABSENT_REASON_EXTENSION_URI)) {
				return theExpectedIdentifiers.stream().anyMatch(s -> s.hasExtension(DATA_ABSENT_REASON_EXTENSION_URI));
			}
			return false;
		});
	}

	private static Stream<Arguments> multipleCardinalityArguments() {
		return Stream.of(
			 Arguments.of(List.of(), List.of(), List.of()),
			 Arguments.of(List.of(identifierFromValue("identifier1")), List.of(), List.of(identifierFromValue("identifier1"))),
			 Arguments.of(List.of(), List.of(identifierFromValue("identifier1")), List.of(identifierFromValue("identifier1"))),
			 Arguments.of(List.of(identifierFromValue("identifier1")), List.of(identifierFromValue("identifier2")), List.of(identifierFromValue("identifier1"), identifierFromValue("identifier2"))),
			 Arguments.of(List.of(identifierWithDataAbsentReason()), List.of(), List.of(identifierWithDataAbsentReason())),
			 Arguments.of(List.of(), List.of(identifierWithDataAbsentReason()), List.of(identifierWithDataAbsentReason())),
			 Arguments.of(List.of(identifierWithDataAbsentReason()), List.of(identifierWithDataAbsentReason()), List.of(identifierWithDataAbsentReason())),
			 Arguments.of(List.of(identifierFromValue("identifier1")), List.of(identifierWithDataAbsentReason()), List.of(identifierFromValue("identifier1"))),
			 Arguments.of(List.of(identifierWithDataAbsentReason()), List.of(identifierFromValue("identifier1")), List.of(identifierFromValue("identifier1"))),
			 Arguments.of(List.of(identifierFromValue("identifier1"), identifierFromValue("identifier2")), List.of(identifierWithDataAbsentReason()), List.of(identifierFromValue("identifier1"), identifierFromValue("identifier2"))),
			 Arguments.of(List.of(identifierWithDataAbsentReason()), List.of(identifierFromValue("identifier1"), identifierFromValue("identifier2")), List.of(identifierFromValue("identifier1"), identifierFromValue("identifier2")))
		);
	}

	private static Identifier identifierFromValue(String theValue) {
		return new Identifier().setValue(theValue);
	}

	private static Identifier identifierWithDataAbsentReason() {
		Identifier identifier = new Identifier();
		Enumeration<Enumerations.DataAbsentReason> extension = new Enumeration<>(new Enumerations.DataAbsentReasonEnumFactory(), Enumerations.DataAbsentReason.UNKNOWN);
		identifier.addExtension(DATA_ABSENT_REASON_EXTENSION_URI, extension);
		return identifier;
	}

	@Test
	void testCloneWithDuplicateNonPrimitives() {
		Patient p1 = new Patient();
		Patient p2 = new Patient();

		p1.addName().addGiven("Jim");
		p1.getNameFirstRep().addGiven("George");

		assertThat(p1.getName()).hasSize(1);
		assertThat(p1.getName().get(0).getGiven()).hasSize(2);

		p2.addName().addGiven("Jim");
		p2.getNameFirstRep().addGiven("George");

		assertThat(p2.getName()).hasSize(1);
		assertThat(p2.getName().get(0).getGiven()).hasSize(2);

		TerserUtil.mergeAllFields(ourFhirContext, p1, p2);

		assertThat(p2.getName()).hasSize(1);
		assertThat(p2.getName().get(0).getGiven()).hasSize(2);
	}


	@Test
	void testEqualsFunction() {
		Patient p1 = new Patient();
		Patient p2 = new Patient();

		p1.addName(new HumanName().setFamily("family").addGiven("asd"));
		p2.addName(new HumanName().setFamily("family").addGiven("asd"));

		assertTrue(TerserUtil.equals(p1, p2));
	}

	@Test
	void testEqualsFunctionNotEqual() {
		Patient p1 = new Patient();
		Patient p2 = new Patient();

		p1.addName(new HumanName().setFamily("family").addGiven("asd"));
		p2.addName(new HumanName().setFamily("family").addGiven("asd1"));

		assertFalse(TerserUtil.equals(p1, p2));
	}

	@Test
	void testHasValues() {
		Patient p1 = new Patient();
		p1.addName().setFamily("Doe");

		assertTrue(TerserUtil.hasValues(ourFhirContext, p1, "name"));
		assertFalse(TerserUtil.hasValues(ourFhirContext, p1, "address"));
	}

	@Test
	void testGetValues() {
		Patient p1 = new Patient();
		p1.addName().setFamily("Doe");

		assertEquals("Doe", ((HumanName) TerserUtil.getValueFirstRep(ourFhirContext, p1, "name")).getFamily());
		assertThat(TerserUtil.getValues(ourFhirContext, p1, "name")).isNotEmpty();
		assertNull(TerserUtil.getValues(ourFhirContext, p1, "whoaIsThatReal"));
		assertNull(TerserUtil.getValueFirstRep(ourFhirContext, p1, "whoaIsThatReal"));
	}

	@Test
	public void testReplaceFields() {
		Patient p1 = new Patient();
		p1.addName().setFamily("Doe");
		Patient p2 = new Patient();
		p2.addName().setFamily("Smith");

		TerserUtil.replaceField(ourFhirContext, "name", p1, p2);

		assertThat(p2.getName()).hasSize(1);
		assertEquals("Doe", p2.getName().get(0).getFamily());
	}

	@Test
	public void testReplaceFields_SameValues() {
		Patient p1 = new Patient();
		p1.addName().setFamily("Doe");
		Patient p2 = new Patient();
		p2.setName(p1.getName());

		TerserUtil.replaceField(ourFhirContext, "name", p1, p2);

		assertThat(p2.getName()).hasSize(1);
		assertEquals("Doe", p2.getName().get(0).getFamily());
	}

	@Test
	public void testReplaceFieldByEmptyValue() {
		Patient p1 = new Patient();
		Patient p2 = new Patient();
		p2.setActive(true);

		TerserUtil.replaceField(ourFhirContext, "active", p1, p2);

		// expect p2 to have 'active removed'
		assertFalse(p2.hasActive());
	}

	@Test
	public void testReplaceFieldsByPredicate() {
		Patient p1 = new Patient();
		p1.addName().setFamily("Doe");
		p1.setGender(Enumerations.AdministrativeGender.MALE);

		Patient p2 = new Patient();
		p2.addName().setFamily("Smith");
		Date dob = new Date();
		p2.setBirthDate(dob);

		TerserUtil.replaceFieldsByPredicate(ourFhirContext, p1, p2, TerserUtil.EXCLUDE_IDS_META_AND_EMPTY);

		// expect p2 to have "Doe" and MALE after replace
		assertThat(p2.getName()).hasSize(1);
		assertEquals("Doe", p2.getName().get(0).getFamily());

		assertEquals(Enumerations.AdministrativeGender.MALE, p2.getGender());
		assertEquals(dob, p2.getBirthDate());
	}

	@Test
	public void testClearFields() {
		{
			Patient p1 = new Patient();
			p1.addName().setFamily("Doe");
			assertThat(p1.getName()).hasSize(1);

			TerserUtil.clearField(ourFhirContext, p1, "name");

			assertThat(p1.getName()).isEmpty();
		}

		{
			Address a1 = new Address();
			a1.addLine("Line 1");
			a1.addLine("Line 2");
			assertThat(a1.getLine()).hasSize(2);
			a1.setCity("Test");
			TerserUtil.clearField(ourFhirContext, "line", a1);

			assertThat(a1.getLine()).isEmpty();
			assertEquals("Test", a1.getCity());
		}
	}

	@Test
	public void testClearFieldByFhirPath() {
		Patient p1 = new Patient();
		p1.addName().setFamily("Doe");
		assertThat(p1.getName()).hasSize(1);

		TerserUtil.clearFieldByFhirPath(ourFhirContext, p1, "name");

		assertThat(p1.getName()).isEmpty();

		Address a1 = new Address();
		a1.addLine("Line 1");
		a1.addLine("Line 2");
		assertThat(a1.getLine()).hasSize(2);
		a1.setCity("Test");
		a1.getPeriod().setStartElement(new DateTimeType("2021-01-01"));
		p1.addAddress(a1);

		assertEquals("2021-01-01", p1.getAddress().get(0).getPeriod().getStartElement().toHumanDisplay());
		assertNotNull(p1.getAddress().get(0).getPeriod().getStart());

		Address a2 = new Address();
		a2.addLine("Line 1");
		a2.addLine("Line 2");
		a2.setCity("Test");
		a2.getPeriod().setStartElement(new DateTimeType("2021-01-01"));
		p1.addAddress(a2);


		TerserUtil.clearFieldByFhirPath(ourFhirContext, p1, "address.line");
		TerserUtil.clearFieldByFhirPath(ourFhirContext, p1, "address.period.start");

		assertNull(p1.getAddress().get(0).getPeriod().getStart());

		assertThat(p1.getAddress()).hasSize(2);
		assertThat(p1.getAddress().get(0).getLine()).isEmpty();
		assertThat(p1.getAddress().get(1).getLine()).isEmpty();
		assertEquals("Test", p1.getAddress().get(0).getCity());
		assertEquals("Test", p1.getAddress().get(1).getCity());
	}

	@Test
	void testRemoveByFhirPath() {
		// arrange
		Claim claimWithReferences = createClaim();
		claimWithReferences.setPatient(new Reference("Patient/123"));
		String fhirPath = "patient";
		assertTrue(claimWithReferences.hasPatient());
		//act
		TerserUtil.clearFieldByFhirPath(ourFhirContext, claimWithReferences, fhirPath);
		//assert
		assertFalse(claimWithReferences.hasPatient());
	}

	static Claim createClaim() {
		Claim claim = new Claim();
		claim.setStatus(Claim.ClaimStatus.ACTIVE);
		return claim;
	}

	@Test
	public void testSetField() {
		Patient p1 = new Patient();

		Address address = new Address();
		address.setCity("CITY");

		TerserUtil.setField(ourFhirContext, "address", p1, address);

		assertThat(p1.getAddress()).hasSize(1);
		assertEquals("CITY", p1.getAddress().get(0).getCity());
	}

	@Test
	public void testSetFieldByFhirPath() {
		Patient p1 = new Patient();

		Address address = new Address();
		address.setCity("CITY");

		TerserUtil.setFieldByFhirPath(ourFhirContext, "address", p1, address);

		assertThat(p1.getAddress()).hasSize(1);
		assertEquals("CITY", p1.getAddress().get(0).getCity());
	}

	@Test
	public void testSetFieldByCompositeFhirPath() {
		Patient p1 = new Patient();

		TerserUtil.setFieldByFhirPath(ourFhirContext, "address.city", p1, new StringType("CITY"));

		assertThat(p1.getAddress()).hasSize(1);
		assertEquals("CITY", p1.getAddress().get(0).getCity());
	}

	@Test
	public void testClone() {
		Patient p1 = new Patient();
		p1.addName().setFamily("Doe").addGiven("Joe");

		Patient p2 = TerserUtil.clone(ourFhirContext, p1);

		assertEquals(p1.getName().get(0).getNameAsSingleString(), p2.getName().get(0).getNameAsSingleString());
		assertTrue(p1.equalsDeep(p2));
	}

	@Test
	public void testNewElement() {
		assertNotNull((IBase)TerserUtil.newElement(ourFhirContext, "string"));
		assertEquals(1, ((PrimitiveType) TerserUtil.newElement(ourFhirContext, "integer", "1")).getValue());

		assertNotNull((IBase)TerserUtil.newElement(ourFhirContext, "string"));
		assertNull(((PrimitiveType) TerserUtil.newElement(ourFhirContext, "integer")).getValue());

		assertNotNull((IBase)TerserUtil.newElement(ourFhirContext, "string", null));
		assertNull(((PrimitiveType) TerserUtil.newElement(ourFhirContext, "integer", null)).getValue());
	}

	@Test
	public void testNewResource() {
		assertNotNull((IBase)TerserUtil.newResource(ourFhirContext, "Patient"));
		assertNotNull((IBase)TerserUtil.newResource(ourFhirContext, "Patient", null));
	}

	@Test
	public void testInstantiateBackboneElement() {
		IBaseBackboneElement patientContact = TerserUtil.instantiateBackboneElement(ourFhirContext, "Patient", "contact");
		assertNotNull(patientContact);
		assertEquals(Patient.ContactComponent.class, patientContact.getClass());
		assertTrue(patientContact.isEmpty());
	}

}
