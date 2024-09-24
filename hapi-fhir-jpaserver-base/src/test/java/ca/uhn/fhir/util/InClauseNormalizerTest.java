package ca.uhn.fhir.util;

import ca.uhn.fhir.jpa.util.InClauseNormalizer;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static java.util.Collections.nCopies;
import static java.util.Collections.unmodifiableList;
import static org.assertj.core.api.Assertions.assertThat;

public class InClauseNormalizerTest {
	private static final Long ourResourceId = 1L;
	private static final Long ourPaddingValue = -1L;

	@ParameterizedTest
	@MethodSource("arguments")
	public void testNormalizeUnmodifiableList_willCreateNewListAndPadToSize(int theInitialListSize, int theExpectedNormalizedListSize) {
		List<Long> initialList = new ArrayList<>(nCopies(theInitialListSize, ourResourceId));
		initialList = unmodifiableList(initialList);

		List<Long> normalizedList = InClauseNormalizer.normalizeIdListForInClause(initialList);

		assertNormalizedList(initialList, normalizedList, theInitialListSize, theExpectedNormalizedListSize);
	}

	@ParameterizedTest
	@MethodSource("arguments")
	public void testNormalizeListToSizeAndPad(int theInitialListSize, int theExpectedNormalizedListSize) {
		List<Long> initialList = new ArrayList<>(nCopies(theInitialListSize, ourResourceId));

		List<Long> normalizedList = InClauseNormalizer.normalizeIdListForInClause(initialList);

		assertNormalizedList(initialList, normalizedList, theInitialListSize, theExpectedNormalizedListSize);
	}

	private void assertNormalizedList(List<Long> theInitialList, List<Long> theNormalizedList, int theInitialListSize, int theExpectedNormalizedListSize) {
		List<Long> expectedPaddedSubList = new ArrayList<>(nCopies(theExpectedNormalizedListSize - theInitialListSize, ourPaddingValue));

		assertThat(theNormalizedList).startsWith(listToArray(theInitialList));
		assertThat(theNormalizedList).hasSize(theExpectedNormalizedListSize);
		assertThat(theNormalizedList).endsWith(listToArray(expectedPaddedSubList));
	}

	static Long[] listToArray(List<Long> theList) {
		return theList.toArray(new Long[0]);
	}

	private static Stream<Arguments> arguments(){
		return Stream.of(
			Arguments.of(0, 0),
			Arguments.of(1, 1),
			Arguments.of(2, 10),
			Arguments.of(10, 10),
			Arguments.of(12, 50),
			Arguments.of(50, 50),
			Arguments.of(51, 100),
			Arguments.of(100, 100),
			Arguments.of(150, 200),
			Arguments.of(300, 500),
			Arguments.of(500, 500),
			Arguments.of(700, 800),
			Arguments.of(800, 800),
			Arguments.of(801, 801)
		);
	}

}