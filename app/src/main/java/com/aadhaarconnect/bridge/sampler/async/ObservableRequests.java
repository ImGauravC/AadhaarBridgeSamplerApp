package com.aadhaarconnect.bridge.sampler.async;

import android.util.Log;

import com.aadhaarconnect.bridge.capture.model.auth.AuthCaptureData;
import com.aadhaarconnect.bridge.capture.model.bfd.BfdCaptureData;
import com.aadhaarconnect.bridge.capture.model.kyc.KycCaptureData;
import com.aadhaarconnect.bridge.capture.model.otp.OtpCaptureData;
import com.aadhaarconnect.bridge.sampler.events.ABSEvent;
import com.aadhaarconnect.bridge.sampler.events.CompletionEvent;
import com.aadhaarconnect.bridge.sampler.events.StartingEvent;
import com.aadhaarconnect.bridge.sampler.util.GsonSerializerUtil;
import com.support.android.designlibdemo.BuildConfig;

import java.io.IOException;
import java.net.CookieManager;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import de.greenrobot.event.EventBus;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.JavaNetCookieJar;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.logging.HttpLoggingInterceptor;

/**
 * Created by gauravchauhan on 1/31/16.
 */
public class ObservableRequests {
    private static final String TAG = ObservableRequests.class.getSimpleName();
    protected static final String CONTENT_HEADER_ACCEPT = "Accept";
    protected static final String CONTENT_TYPE_APPLICATION_JSON = "application/json";
    protected static final String CONTENT_HEADER_TYPE = "Content-Type";
    protected static final int CONNECTION_TIMEOUT = 10000;
    protected static final int SOCKET_TIMEOUT = 60000;

    public static void get(final String url, final AuthCaptureData authData, final ABSEvent event) {
        fetch(url, GsonSerializerUtil.marshall(authData), event);
    }

    public static void get(final String url, final BfdCaptureData authData, final ABSEvent event) {
        fetch(url, GsonSerializerUtil.marshall(authData), event);
    }

    public static void get(final String url, final OtpCaptureData authData, final ABSEvent event) {
        fetch(url, GsonSerializerUtil.marshall(authData), event);
    }

    public static void get(final String url, final KycCaptureData authData, final ABSEvent event) {
        fetch(url, GsonSerializerUtil.marshall(authData), event);
    }

    private static void fetch(final String url, final String authData, final ABSEvent event) {
        EventBus.getDefault().postSticky(new StartingEvent().setEvent(event));
        OkHttpClient client = getAllAcceptingOkHttpClient();

        Request request = new Request.Builder()
                .addHeader(CONTENT_HEADER_TYPE, CONTENT_TYPE_APPLICATION_JSON)
                .addHeader(CONTENT_HEADER_ACCEPT, CONTENT_TYPE_APPLICATION_JSON)
                .post(RequestBody.create(MediaType.parse(CONTENT_TYPE_APPLICATION_JSON), authData))
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                Log.e(TAG, "COMMUNICATION_ERROR : Error while communicating with the server. Check connectivity.", e);
                EventBus.getDefault().postSticky(
                        new CompletionEvent()
                                .setResponseString("COMMUNICATION_ERROR : Error while communicating with the server. Check connectivity.")
                                .setCode(500)
                                .setEventAFailure()
                                .setEvent(event));
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                String responseContent = response.body().string();
                if (response.code() == 200) {
                    EventBus.getDefault().postSticky(
                            new CompletionEvent()
                                    .setResponseString(responseContent)
                                    .setEventASuccess()
                                    .setEvent(event));
                    Log.d(TAG, "RESPONSE : " + responseContent);
                } else {
                    Log.d(TAG, "RESPONSE CODE : " + response.code());
                    EventBus.getDefault().postSticky(
                            new CompletionEvent()
                                    .setResponseString(responseContent)
                                    .setCode(response.code())
                                    .setEventAFailure()
                                    .setEvent(event));
                }
            }
        });
    }


    private static OkHttpClient sOkHttpClient;

    protected static synchronized OkHttpClient getAllAcceptingOkHttpClient() {
        if (sOkHttpClient == null) {
            SSLSocketFactory factory = getAllAcceptingSSLSocketFactory();
            OkHttpClient.Builder builder = new OkHttpClient.Builder()
                    .connectTimeout(CONNECTION_TIMEOUT, TimeUnit.MILLISECONDS)
                    .readTimeout(SOCKET_TIMEOUT, TimeUnit.MILLISECONDS)
                    .writeTimeout(SOCKET_TIMEOUT, TimeUnit.MILLISECONDS);

            builder.cookieJar(new JavaNetCookieJar(new CookieManager()));
            if (factory != null) {
                builder.sslSocketFactory(factory);
            }
            if (BuildConfig.DEBUG) {
                builder.addInterceptor(getLoggingInterceptor());
            }
            sOkHttpClient = builder.build();
        }
        return sOkHttpClient;
    }

    private static HttpLoggingInterceptor getLoggingInterceptor() {
        HttpLoggingInterceptor.Logger logger = new OkHttpLogger("HttpLogs");
        HttpLoggingInterceptor loggingInterceptor = new HttpLoggingInterceptor(logger);
        loggingInterceptor.setLevel(HttpLoggingInterceptor.Level.BODY);
        return loggingInterceptor;
    }

    private static class OkHttpLogger implements HttpLoggingInterceptor.Logger {
        private String mTag;

        public OkHttpLogger(String tag) {
            mTag = tag;
        }

        @Override
        public void log(String message) {
            Log.println(Log.VERBOSE, mTag, message);
        }
    }


    private static SSLSocketFactory getAllAcceptingSSLSocketFactory() {
        try {
            final SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, sTrustAllCerts, new java.security.SecureRandom());
            return sslContext.getSocketFactory();
        } catch (KeyManagementException | NoSuchAlgorithmException e) {
            Log.d(TAG, "", e);
            return null;
        }
    }

    private static final TrustManager[] sTrustAllCerts = new TrustManager[]{
            new X509TrustManager() {
                @Override
                public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
                }

                @Override
                public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException {
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
            }
    };
}
