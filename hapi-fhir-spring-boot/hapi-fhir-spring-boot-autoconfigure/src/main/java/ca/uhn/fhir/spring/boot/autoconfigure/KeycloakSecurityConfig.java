package ca.uhn.fhir.spring.boot.autoconfigure;

import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.AdapterDeploymentContextFactoryBean;
import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.client.KeycloakClientRequestFactory;
import org.keycloak.adapters.springsecurity.client.KeycloakRestTemplate;
import org.keycloak.adapters.springsecurity.config.KeycloakSpringConfigResolverWrapper;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Scope;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

@KeycloakConfiguration
public class KeycloakSecurityConfig extends KeycloakWebSecurityConfigurerAdapter {

	@Autowired
	private KeycloakClientRequestFactory keycloakClientRequestFactory;

	private static final String CORS_ALLOWED_HEADERS = "origin,content-type,accept,x-requested-with,Authorization";

	/**
	 * Registers the KeycloakAuthenticationProvider with the authentication manager.
	 */
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		KeycloakAuthenticationProvider keycloakAuthenticationProvider = keycloakAuthenticationProvider();
		keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(new SimpleAuthorityMapper());
		auth.authenticationProvider(keycloakAuthenticationProvider);
	}

	/**
	 * Defines the session authentication strategy.
	 */
	@Bean
	@Override
	protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
		return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
	}
	
    @Bean
    public KeycloakConfigResolver keycloakConfigResolver() {
        return new KeycloakSpringBootConfigResolver();
    }

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		super.configure(http);
				
		http.authorizeRequests()
        .antMatchers("/**")
        .authenticated()
        .anyRequest()
        .permitAll();
		
		/* @formatter:off */
//		http
//			.csrf().disable() // <- THIS LINE
//			.cors().disable()
//			.authorizeRequests()
////			.antMatchers("/**", "/fhir/**", "/fhir/")
////			.hasAnyRole()
//			.anyRequest()
//			.authenticated();

		//working
/*
 * http.authorizeRequests() .anyRequest() .permitAll(); http.csrf().disable();
 */
		//working end

//		http
//			.authorizeRequests()
//			.anyRequest().authenticated()
//			.and()
//			.csrf()
//			.ignoringAntMatchers("/fhir/**","/fhir/patient/**")
//			.and()
//			.logout()
//			.logoutRequestMatcher(new AntPathRequestMatcher("logout.do", "GET"));

		/* @formatter:on */

	}

//	@Bean
//	public CorsConfigurationSource corsConfigurationSource() {
//		CorsConfiguration configuration = new CorsConfiguration();
//		configuration.setAllowedOrigins(Arrays.asList(opensrpAllowedSources.split(",")));
//		configuration.setAllowedMethods(Arrays.asList(GET.name(), POST.name(), PUT.name(), DELETE.name()));
//		configuration.setAllowedHeaders(Arrays.asList(CORS_ALLOWED_HEADERS.split(",")));
//		configuration.setMaxAge(corsMaxAge);
//		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//		source.registerCorsConfiguration("/**", configuration);
//		return source;
//	}

	@Bean
	@Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE) //TODO why?
	@Autowired
	public KeycloakRestTemplate keycloakRestTemplate() {
		return new KeycloakRestTemplate(keycloakClientRequestFactory);
	}

	/*
	 * @Bean public KeycloakDeployment keycloakDeployment() throws IOException { if
	 * (!keycloakConfigFileResource.isReadable()) { throw new
	 * FileNotFoundException(String.
	 * format("Unable to locate Keycloak configuration file: %s",
	 * keycloakConfigFileResource.getFilename())); }
	 * 
	 * try (InputStream inputStream = keycloakConfigFileResource.getInputStream()) {
	 * return KeycloakDeploymentBuilder.build(inputStream); }
	 * 
	 * }
	 */

	/*
	 * @Bean
	 * 
	 * @Override protected AdapterDeploymentContext adapterDeploymentContext()
	 * throws Exception { AdapterDeploymentContextFactoryBean factoryBean; if
	 * (this.KeycloakConfigResolver() != null) { factoryBean = new
	 * AdapterDeploymentContextFactoryBean(new
	 * KeycloakSpringConfigResolverWrapper(this.KeycloakConfigResolver())); } else {
	 * factoryBean = new
	 * AdapterDeploymentContextFactoryBean(this.keycloakConfigFileResource); }
	 * 
	 * factoryBean.afterPropertiesSet(); return factoryBean.getObject(); }
	 */

}
