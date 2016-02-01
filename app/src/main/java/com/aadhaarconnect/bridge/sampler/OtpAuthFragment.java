package com.aadhaarconnect.bridge.sampler;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.support.annotation.Nullable;
import android.support.design.widget.FloatingActionButton;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.Toast;

import com.aadhaarconnect.bridge.capture.model.auth.AuthCaptureData;
import com.aadhaarconnect.bridge.capture.model.auth.AuthCaptureRequest;
import com.aadhaarconnect.bridge.capture.model.common.Location;
import com.aadhaarconnect.bridge.capture.model.common.LocationType;
import com.aadhaarconnect.bridge.capture.model.common.request.CertificateType;
import com.aadhaarconnect.bridge.capture.model.common.request.Modality;
import com.aadhaarconnect.bridge.capture.model.otp.OtpCaptureData;
import com.aadhaarconnect.bridge.capture.model.otp.OtpCaptureRequest;
import com.aadhaarconnect.bridge.capture.model.otp.OtpChannel;
import com.aadhaarconnect.bridge.gateway.model.AuthResponse;
import com.aadhaarconnect.bridge.gateway.model.OtpResponse;
import com.aadhaarconnect.bridge.sampler.async.ObservableRequests;
import com.aadhaarconnect.bridge.sampler.events.ABSEvent;
import com.aadhaarconnect.bridge.sampler.events.CompletionEvent;
import com.aadhaarconnect.bridge.sampler.events.StartingEvent;
import com.aadhaarconnect.bridge.sampler.util.AadhaarNumberFormatter;
import com.aadhaarconnect.bridge.sampler.util.GsonSerializerUtil;
import com.support.android.designlibdemo.R;

import de.greenrobot.event.EventBus;

public class OtpAuthFragment extends EventFragment implements Constants {
    public static final int AADHAAR_CONNECT_AUTH_REQUEST = 1001;
    public static final int AADHAAR_CONNECT_OTP_REQUEST = 1002;
    public static final String AADHAAR_CONNECT_RESPONSE = "RESPONSE";
    protected static final String LOG_TAG = OtpAuthFragment.class.getSimpleName();

    private EditText aadhaarTextView;
    private EditText otpTextView;
    private AuthCaptureData authCaptureData;
    private OtpCaptureData otpCaptureData;
    private SharedPreferences prefs;
    private boolean isEditable = true;

    @Nullable
    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View rv = inflater.inflate(
                R.layout.otp_auth_view, container, false);

        aadhaarTextView = (EditText) rv.findViewById(R.id.aadhaarId);
        otpTextView = (EditText) rv.findViewById(R.id.otp);
        prefs = PreferenceManager.getDefaultSharedPreferences(getActivity());

        FloatingActionButton fab = (FloatingActionButton) rv.findViewById(R.id.auth);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (otpTextView.getVisibility() == View.VISIBLE) {
                    authenticate(view);
                } else {
                    generateOtp(view);
                }
            }
        });

        aadhaarTextView.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                if (isEditable) {
                    isEditable = false;
                    String aadhaar = AadhaarNumberFormatter.formatWithSpaces(s.toString());
                    aadhaarTextView.setText(aadhaar);
                    aadhaarTextView.setSelection(aadhaar.length());
                } else {
                    isEditable = true;
                }
            }

            @Override
            public void afterTextChanged(Editable s) {

            }
        });

        return rv;

    }

    public void authenticate(View v) {
        if (TextUtils.isEmpty(aadhaarTextView.getText())) {
            showToast(
                    "Invalid Aadhaar Number. Please enter a valid Aadhaar Number",
                    Toast.LENGTH_LONG);
            return;
        }

        if (TextUtils.isEmpty(otpTextView.getText())) {
            showToast(
                    "No OTP Entered",
                    Toast.LENGTH_LONG);
            return;
        }

        AuthCaptureRequest authCaptureRequest = new AuthCaptureRequest();
        authCaptureRequest.setAadhaar(aadhaarTextView.getText().toString().replaceAll("\\s", ""));
        authCaptureRequest.setModality(Modality.otp);
        if (prefs.getAll().isEmpty()) {
            Log.d(LOG_TAG, "Environment Prefs not set");
            authCaptureRequest.setCertificateType(CertificateType.preprod);
        } else {
            Log.d(LOG_TAG, "Using set Environment prefs");
            String env = prefs.getString("environment", PREPROD);
            if (TextUtils.equals(env, PREPROD)) {
                authCaptureRequest.setCertificateType(CertificateType.preprod);
            } else if (TextUtils.equals(env, PROD)) {
                authCaptureRequest.setCertificateType(CertificateType.prod);
            }
        }
        authCaptureRequest.setOtp(otpTextView.getText().toString());

        Location loc = new Location();
        loc.setType(LocationType.pincode);
        loc.setPincode("560076");
        authCaptureRequest.setLocation(loc);

        Intent i = new Intent();
        i = new Intent("com.aadhaarconnect.bridge.action.AUTHCAPTURE");
        i.putExtra("REQUEST", GsonSerializerUtil.marshall(authCaptureRequest));
        try {
            startActivityForResult(i, AADHAAR_CONNECT_AUTH_REQUEST);
        } catch (Exception e) {
            Log.e(LOG_TAG, "ERROR : " + e.getMessage());
        }
    }

    public void generateOtp(View v) {
        if (TextUtils.isEmpty(aadhaarTextView.getText())) {
            showToast(
                    "Invalid Aadhaar Number. Please enter a valid Aadhaar Number",
                    Toast.LENGTH_LONG);
            return;
        }

        OtpCaptureRequest otpCaptureRequest = new OtpCaptureRequest();
        otpCaptureRequest.setAadhaar(aadhaarTextView.getText().toString().replaceAll("\\s", ""));
        if (prefs.getAll().isEmpty()) {
            Log.d(LOG_TAG, "Environment Prefs not set");
            otpCaptureRequest.setCertificateType(CertificateType.preprod);
        } else {
            Log.d(LOG_TAG, "Using set Environment prefs");
            String env = prefs.getString("environment", PREPROD);
            if (TextUtils.equals(env, PREPROD)) {
                otpCaptureRequest.setCertificateType(CertificateType.preprod);
            } else if (TextUtils.equals(env, PROD)) {
                otpCaptureRequest.setCertificateType(CertificateType.prod);
            }
        }
        otpCaptureRequest.setChannel(OtpChannel.SMS);

        Location loc = new Location();
        loc.setType(LocationType.pincode);
        loc.setPincode("560076");
        otpCaptureRequest.setLocation(loc);

        Intent i = new Intent();
        i = new Intent("com.aadhaarconnect.bridge.action.OTPCAPTURE");
        i.putExtra("REQUEST", GsonSerializerUtil.marshall(otpCaptureRequest));
        try {
            startActivityForResult(i, AADHAAR_CONNECT_OTP_REQUEST);
        } catch (Exception e) {
            Log.e(LOG_TAG, "ERROR : " + e.getMessage());
        }
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        Log.d(LOG_TAG, "requestCode : " + requestCode + ",resultCode : " + resultCode + data == null ? ",data is null" : "");
        if (resultCode == Activity.RESULT_OK && requestCode == AADHAAR_CONNECT_OTP_REQUEST && data != null) {
            String responseStr = data.getStringExtra(AADHAAR_CONNECT_RESPONSE);
            otpCaptureData = GsonSerializerUtil.unmarshal(responseStr, OtpCaptureData.class);

            Log.d(LOG_TAG, "otpCaptureData : " + responseStr);

            if (prefs.getAll().isEmpty()) {
                Log.d(LOG_TAG, "URL Prefs not set");
                ObservableRequests.get("https://ac.khoslalabs.com/hackgate/hackathon/otp", otpCaptureData, ABSEvent.GENERATE_OTP);
            } else {
                Log.d(LOG_TAG, "Using set URL prefs");
                ObservableRequests.get(prefs.getString("serverHost", "https://ac.khoslalabs.com/hackgate/hackathon") + "/otp", otpCaptureData, ABSEvent.GENERATE_OTP);
            }
        }
        if (resultCode == Activity.RESULT_OK && requestCode == AADHAAR_CONNECT_AUTH_REQUEST && data != null) {
            String responseStr = data.getStringExtra(AADHAAR_CONNECT_RESPONSE);
            authCaptureData = GsonSerializerUtil.unmarshal(responseStr, AuthCaptureData.class);

            Log.d(LOG_TAG, "authCaptureData : " + responseStr);


            if (prefs.getAll().isEmpty()) {
                Log.d(LOG_TAG, "URL Prefs not set");
                ObservableRequests.get("https://ac.khoslalabs.com/hackgate/hackathon/auth", authCaptureData, ABSEvent.OTP);
            } else {
                Log.d(LOG_TAG, "Using set URL prefs");
                ObservableRequests.get(prefs.getString("serverHost", "https://ac.khoslalabs.com/hackgate/hackathon") + "/auth", authCaptureData, ABSEvent.IRIS);
            }
        }
    }

    private void showToast(String text, int duration) {
        Toast toast = Toast.makeText(this.getActivity(), text, duration);
        toast.show();
    }

    public void onEventMainThread(StartingEvent event) {
        showProgressDialog();
        EventBus.getDefault().removeStickyEvent(StartingEvent.class);
    }

    public void onEventMainThread(CompletionEvent event) {
        dismissProgressDialog();

        if (event.WasEventASuccess()) {
            switch (event.getEvent()) {
                case OTP:
                    AuthResponse authResponse = GsonSerializerUtil.unmarshal(event.getResponseString(), AuthResponse.class);
                    if (authResponse.isSuccess()) {
                        Intent i = new Intent(getActivity(), ResultActivity.class);
                        i.putExtra(RESULT_TYPE, AUTH);
                        i.putExtra(AUTHCAPTUREDATA, GsonSerializerUtil.marshall(authCaptureData));
                        i.putExtra(AUTHRESPONSE, GsonSerializerUtil.marshall(authResponse));
                        startActivity(i);
                    } else {
                        AlertDialog alertDialog = new AlertDialog.Builder(getActivity()).create();
                        alertDialog.setTitle("Status");

                        String msg = "Auth Status: " + (authResponse.isSuccess() ? "success" : "fail")
                                + (null != authResponse.getReferenceCode() ? "\nRefcode: " + authResponse.getReferenceCode() : "")
                                + (null != authResponse.getStatusCode() ? "\nStatusCode: " + authResponse.getStatusCode() : "");
                        alertDialog.setMessage(msg);
                        alertDialog.setButton("OK", new DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog, int which) {
                                dialog.dismiss();
                            }
                        });

                        alertDialog.show();
                    }
                    break;
                case GENERATE_OTP:
                    OtpResponse otpResponse = GsonSerializerUtil.unmarshal(event.getResponseString(), OtpResponse.class);
                    if (otpResponse.isSuccess()) {
                        otpTextView.setVisibility(View.VISIBLE);
                        showToast("OTP generated successfully", Toast.LENGTH_LONG);
                    } else {
                        AlertDialog alertDialog = new AlertDialog.Builder(getActivity()).create();
                        alertDialog.setTitle("Status");

                        String msg = "Auth Status: " + (otpResponse.isSuccess() ? "success" : "fail")
                                + (null != otpResponse.getReferenceCode() ? "\nRefcode: " + otpResponse.getReferenceCode() : "")
                                + (null != otpResponse.getStatusCode() ? "\nStatusCode: " + otpResponse.getStatusCode() : "");
                        alertDialog.setMessage(msg);
                        alertDialog.setButton("OK", new DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog, int which) {
                                dialog.dismiss();
                            }
                        });

                        alertDialog.show();
                    }
                default:
                    break;
            }
        } else {
            AlertDialog alertDialog = new AlertDialog.Builder(getActivity()).create();
            String msg = "";
            switch (event.getEvent()) {
                case OTP:
                    alertDialog.setTitle("Status");

                    msg = "Auth Status: fail\n"
                            + ("Error, code is : " + event.getCode());
                    alertDialog.setMessage(msg);
                    alertDialog.setButton("OK", new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int which) {
                            dialog.dismiss();
                        }
                    });
                    break;
                case GENERATE_OTP:
                    alertDialog = new AlertDialog.Builder(getActivity()).create();
                    alertDialog.setTitle("Status");

                    msg = "OTP Generation Status: fail\n"
                            + ("Error, code is : " + event.getCode());
                    alertDialog.setMessage(msg);
                    alertDialog.setButton("OK", new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int which) {
                            dialog.dismiss();
                        }
                    });
            }
        }
        EventBus.getDefault().removeStickyEvent(CompletionEvent.class);
    }
}
