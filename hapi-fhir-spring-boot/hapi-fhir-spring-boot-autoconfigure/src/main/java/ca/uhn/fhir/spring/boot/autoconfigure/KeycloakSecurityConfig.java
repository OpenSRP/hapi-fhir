package ca.uhn.fhir.spring.boot.autoconfigure;

import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.AdapterDeploymentContextFactoryBean;
import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.config.KeycloakSpringConfigResolverWrapper;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

@KeycloakConfiguration
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class KeycloakSecurityConfig extends KeycloakWebSecurityConfigurerAdapter {

	@Value("${keycloak.configurationFile:keycloak.json}")
	private Resource keycloakConfigFileResource;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
        http.authorizeRequests()
            .anyRequest()
            .permitAll();
        http.csrf().disable();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        KeycloakAuthenticationProvider keycloakAuthenticationProvider = keycloakAuthenticationProvider();
        keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(new SimpleAuthorityMapper());
        auth.authenticationProvider(keycloakAuthenticationProvider);
    }

    @Bean
    @Override
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    @Bean
    public KeycloakConfigResolver KeycloakConfigResolver() {
        return new KeycloakSpringBootConfigResolver();
    }

	@Bean
	public KeycloakDeployment keycloakDeployment() throws IOException {
		if (!keycloakConfigFileResource.isReadable()) {
			throw new FileNotFoundException(String.format("Unable to locate Keycloak configuration file: %s",
				keycloakConfigFileResource.getFilename()));
		}

		try(InputStream inputStream=keycloakConfigFileResource.getInputStream()){
			return KeycloakDeploymentBuilder.build(inputStream);
		}

	}

	@Bean
	protected AdapterDeploymentContext adapterDeploymentContext() throws Exception {
		AdapterDeploymentContextFactoryBean factoryBean;
		if (this.KeycloakConfigResolver() != null) {
			factoryBean = new AdapterDeploymentContextFactoryBean(new KeycloakSpringConfigResolverWrapper(this.KeycloakConfigResolver()));
		} else {
			factoryBean = new AdapterDeploymentContextFactoryBean(this.keycloakConfigFileResource);
		}

		factoryBean.afterPropertiesSet();
		return factoryBean.getObject();
	}

}
