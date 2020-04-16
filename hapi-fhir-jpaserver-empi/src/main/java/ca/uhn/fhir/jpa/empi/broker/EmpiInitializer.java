package ca.uhn.fhir.jpa.empi.broker;

import ca.uhn.fhir.empi.api.IEmpiProperties;
import ca.uhn.fhir.empi.api.IEmpiRuleValidator;
import ca.uhn.fhir.empi.provider.EmpiProviderLoader;
import ca.uhn.fhir.interceptor.api.IInterceptorService;
import ca.uhn.fhir.jpa.empi.interceptor.EmpiInterceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Service;

@Service
public class EmpiInitializer {
	private static final Logger ourLog = LoggerFactory.getLogger(EmpiInitializer.class);
	public static final String EMPI_CONSUMER_COUNT_DEFAULT = "5";

	@Autowired
	ApplicationContext myApplicationContext;
	@Autowired
	IInterceptorService myInterceptorService;
	@Autowired
	IEmpiProperties myEmpiConfig;
	@Autowired
	IEmpiRuleValidator myEmpiRuleValidator;
	@Autowired
	EmpiSubscriptionLoader myEmpiSubscriptionLoader;
	@Autowired
	EmpiInterceptor myEmpiInterceptor;

	@EventListener(classes = {ContextRefreshedEvent.class})
	// FIXME KHS this can probably go now
	// This @Order is here to ensure that MatchingQueueSubscriberLoader has initialized before we initialize this.
	// Otherwise the EMPI subscriptions won't get loaded into the SubscriptionRegistry
	@Order
	public void init() {
		if (!myEmpiConfig.isEnabled()) {
			return;
		}
		myEmpiRuleValidator.validate(myEmpiConfig.getEmpiRules());
		myInterceptorService.registerInterceptor(myEmpiInterceptor);
		ourLog.info("EMPI interceptor registered");

		EmpiProviderLoader empiProviderLoader = myApplicationContext.getBean(EmpiProviderLoader.class);
		empiProviderLoader.loadProvider();

		myEmpiSubscriptionLoader.daoUpdateEmpiSubscriptions();
	}
}