/*
 *  Copyright (c) 2022 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Bayerische Motoren Werke Aktiengesellschaft (BMW AG) - Initial implementation
 *
 */

package org.eclipse.dataspaceconnector.core.base;

import okhttp3.EventListener;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.Response;
import org.eclipse.dataspaceconnector.spi.EdcException;
import org.eclipse.dataspaceconnector.spi.EdcSetting;
import org.eclipse.dataspaceconnector.spi.system.ServiceExtensionContext;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import static java.lang.String.format;
import static java.util.Optional.ofNullable;

import javax.net.ssl.*;
import java.net.*;
import java.security.cert.CertificateException;

public class OkHttpClientFactory {

    @EdcSetting(value = "If true, enable HTTPS call enforcement. Default value is 'false'", type = "boolean")
    public static final String EDC_HTTP_ENFORCE_HTTPS = "edc.http.enforce-https";

    /**
     * Create an OkHttpClient instance
     *
     * @param context the service extension context
     * @param okHttpEventListener used to instrument OkHttp client for collecting metrics, can be null
     * @return the OkHttpClient
     */
    @NotNull
    public static OkHttpClient create(ServiceExtensionContext context, EventListener okHttpEventListener) {
        var builder = new OkHttpClient.Builder();
        
        //builder = configureToIgnoreCertificate(builder); 
        builder.connectTimeout(30, TimeUnit.SECONDS);
        builder.readTimeout(30, TimeUnit.SECONDS);

        ofNullable(okHttpEventListener).ifPresent(builder::eventListener);

        boolean enforceHttps = context.getSetting(EDC_HTTP_ENFORCE_HTTPS, false);
        if (enforceHttps) {
            builder.addInterceptor(new EnforceHttps());
        } else {
            context.getMonitor().info("HTTPS enforcement it not enabled, please enable it in a production environment");
        }

        return builder.build();
    }

    private static class EnforceHttps implements Interceptor {
        @NotNull
        @Override
        public Response intercept(@NotNull Chain chain) throws IOException {
            var request = chain.request();
            if (!request.isHttps()) {
                throw new EdcException(format("HTTP call to %s blocked due to HTTPS enforcement enabled", request.url()));
            }
            return chain.proceed(request);
        }
    }
    
    private static OkHttpClient.Builder configureToIgnoreCertificate(OkHttpClient.Builder builder) {
        try {

            // Create a trust manager that does not validate certificate chains
            final TrustManager[] trustAllCerts = new TrustManager[] {
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType)
                                throws CertificateException {
                        }

                        @Override
                        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType)
                                throws CertificateException {
                        }

                        @Override
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return new java.security.cert.X509Certificate[]{};
                        }
                    }
            };

            // Install the all-trusting trust manager
            final SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            // Create an ssl socket factory with our all-trusting manager
            final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            builder.sslSocketFactory(sslSocketFactory, (X509TrustManager)trustAllCerts[0]);
            builder.hostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            });
        } catch (Exception e) {
           
        }
        return builder;
    }

}
