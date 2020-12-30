package com.dotcms.osgi.oauth.app;

import java.io.Serializable;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;
import com.dotcms.security.apps.AppSecrets;
import com.dotcms.security.apps.Secret;
import com.dotmarketing.beans.Host;
import com.dotmarketing.business.APILocator;
import com.dotmarketing.business.web.WebAPILocator;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.vavr.control.Try;

@JsonDeserialize(builder = AppConfig.Builder.class)
public class AppConfig implements Serializable {


    private static final long serialVersionUID = 1L;


    public final boolean enableBackend, enableFrontend;
    public final String provider, apiKey, protectedResource, groupResource;
    public final char[] apiSecret;
    public final String[] scope;
    public final Map<String, String> extraParameters;


    private AppConfig(Builder builder) {
        this.enableBackend = builder.enableBackend;
        this.enableFrontend = builder.enableFrontend;
        this.protectedResource = builder.protectedResource;
        this.groupResource = builder.groupResource;
        this.provider = builder.provider;
        this.apiKey = builder.apiKey;
        this.apiSecret = builder.apiSecret;
        this.scope = builder.scope;
        this.extraParameters = builder.extraParameters;
    }


    /**
     * Gets the secrets from the App - this will check the current host then the SYSTEMM_HOST for a
     * valid configuration. This lookup is low overhead and cached by dotCMS.
     * 
     * @param request
     * @return
     */
    public Optional<AppConfig> config(final HttpServletRequest request) {


        final Host host = WebAPILocator.getHostWebAPI().getCurrentHostNoThrow(request);

        Optional<AppSecrets> appSecrets = Try.of(
                        () -> APILocator.getAppsAPI().getSecrets(AppKeys.APP_KEY, true, host, APILocator.systemUser()))
                        .getOrElse(Optional.empty());

        if (!appSecrets.isPresent()) {
            return Optional.empty();
        }

        final Map<String, Secret> secrets = appSecrets.get().getSecrets();


        boolean enableBackend =
                        Try.of(() -> secrets.get(AppKeys.ENABLE_BACKEND.key).getBoolean()).getOrElse(Boolean.FALSE);
        boolean enableFrontend =
                        Try.of(() -> secrets.get(AppKeys.ENABLE_FRONTEND.key).getBoolean()).getOrElse(Boolean.FALSE);

        if (!enableBackend && !enableFrontend) {
            return Optional.empty();
        }

        String provider = Try.of(() -> secrets.get(AppKeys.PROVIDER.key).getString().trim()).getOrNull();
        String protectedResource = Try.of(() -> secrets.get(AppKeys.PROTECTED_RESOURCE.key).getString().trim()).getOrNull();
        String groupResource = Try.of(() -> secrets.get(AppKeys.GROUP_RESOURCE.key).getString().trim()).getOrNull();
        String apiKey = Try.of(() -> secrets.get(AppKeys.API_KEY.key).getString().trim()).getOrNull();
        char[] apiSecret = Try.of(() -> secrets.get(AppKeys.API_SECRET.key).getValue()).getOrElse(new char[0]);
        String[] scope = Try.of(() -> secrets.get(AppKeys.SCOPE.key).getString().split("[, ]"))
                        .getOrElse(new String[0]);


        Map<String, String> extraParameters = null;


        AppConfig config = AppConfig.builder()
                        .withApiKey(apiKey)
                        .withApiSecret(apiSecret)
                        .withEnableBackend(enableBackend)
                        .withEnableFrontend(enableFrontend)
                        .withExtraParameters(extraParameters)
                        .withGroupResource(groupResource)
                        .withProtectedResource(protectedResource)
                        .withProvider(provider)
                        .withScope(scope).build();


        return Optional.ofNullable(config);


    }


    /**
     * Creates builder to build {@link AppConfig}.
     * 
     * @return created builder
     */

    public static Builder builder() {
        return new Builder();
    }


    /**
     * Creates a builder to build {@link AppConfig} and initialize it with the given object.
     * 
     * @param appConfig to initialize the builder with
     * @return created builder
     */

    public static Builder from(AppConfig appConfig) {
        return new Builder(appConfig);
    }


    /**
     * Builder to build {@link AppConfig}.
     */

    public static final class Builder {
        private boolean enableBackend;
        private boolean enableFrontend;
        private String protectedResource;
        private String groupResource;
        private String provider;
        private String apiKey;
        private char[] apiSecret;
        private String[] scope;
        private Map<String, String> extraParameters = Collections.emptyMap();

        private Builder() {}

        private Builder(AppConfig appConfig) {
            this.enableBackend = appConfig.enableBackend;
            this.enableFrontend = appConfig.enableFrontend;
            this.protectedResource = appConfig.protectedResource;
            this.groupResource = appConfig.groupResource;
            this.provider = appConfig.provider;
            this.apiKey = appConfig.apiKey;
            this.apiSecret = appConfig.apiSecret;
            this.scope = appConfig.scope;
            this.extraParameters = appConfig.extraParameters;
        }

        public Builder withEnableBackend(@Nonnull boolean enableBackend) {
            this.enableBackend = enableBackend;
            return this;
        }

        public Builder withEnableFrontend(@Nonnull boolean enableFrontend) {
            this.enableFrontend = enableFrontend;
            return this;
        }

        public Builder withProtectedResource(@Nonnull String protectedResource) {
            this.protectedResource = protectedResource;
            return this;
        }

        public Builder withGroupResource(@Nonnull String groupResource) {
            this.groupResource = groupResource;
            return this;
        }

        public Builder withProvider(@Nonnull String provider) {
            this.provider = provider;
            return this;
        }

        public Builder withApiKey(@Nonnull String apiKey) {
            this.apiKey = apiKey;
            return this;
        }

        public Builder withApiSecret(@Nonnull char[] apiSecret) {
            this.apiSecret = apiSecret;
            return this;
        }



        public Builder withScope(@Nonnull String[] scope) {
            this.scope = scope;
            return this;
        }

        public Builder withExtraParameters(@Nonnull Map<String, String> extraParameters) {
            this.extraParameters = extraParameters;
            return this;
        }

        public AppConfig build() {
            return new AppConfig(this);
        }
    }


}
