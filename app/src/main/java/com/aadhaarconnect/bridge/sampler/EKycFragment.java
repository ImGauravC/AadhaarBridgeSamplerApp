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
import android.widget.RadioButton;
import android.widget.TextView;
import android.widget.Toast;

import com.aadhaarconnect.bridge.capture.model.auth.AuthCaptureRequest;
import com.aadhaarconnect.bridge.capture.model.common.ConsentType;
import com.aadhaarconnect.bridge.capture.model.common.Location;
import com.aadhaarconnect.bridge.capture.model.common.LocationType;
import com.aadhaarconnect.bridge.capture.model.common.request.CertificateType;
import com.aadhaarconnect.bridge.capture.model.common.request.Modality;
import com.aadhaarconnect.bridge.capture.model.common.request.ModalityType;
import com.aadhaarconnect.bridge.capture.model.kyc.KycCaptureData;
import com.aadhaarconnect.bridge.capture.model.kyc.KycCaptureRequest;
import com.aadhaarconnect.bridge.gateway.model.KycResponse;
import com.aadhaarconnect.bridge.sampler.async.ObservableRequests;
import com.aadhaarconnect.bridge.sampler.events.ABSEvent;
import com.aadhaarconnect.bridge.sampler.events.CompletionEvent;
import com.aadhaarconnect.bridge.sampler.events.StartingEvent;
import com.aadhaarconnect.bridge.sampler.util.AadhaarNumberFormatter;
import com.aadhaarconnect.bridge.sampler.util.GsonSerializerUtil;
import com.google.gson.Gson;
import com.support.android.designlibdemo.R;

import de.greenrobot.event.EventBus;

public class EKycFragment extends EventFragment implements Constants {
    public static final int AADHAAR_CONNECT_KYC_REQUEST = 1005;
    public static final String AADHAAR_CONNECT_RESPONSE = "RESPONSE";
    public static final String LOG_TAG = EKycFragment.class.getSimpleName();
    private EditText aadhaarTextView;
    private TextView numberTextView;
    private KycCaptureData kycCaptureData;
    private int numberOffCapture = 2;
    private boolean isFpKyc = true;

    private SharedPreferences prefs;
    private boolean isEditable = true;

    @Nullable
    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View rv = inflater.inflate(
                R.layout.kyc_view, container, false);

        aadhaarTextView = (EditText) rv.findViewById(R.id.aadhaarId);
        numberTextView = (TextView) rv.findViewById(R.id.number);
        prefs = PreferenceManager.getDefaultSharedPreferences(getActivity());

        final RadioButton fp = (RadioButton) rv.findViewById(R.id.fp);
        final RadioButton iris = (RadioButton) rv.findViewById(R.id.iris);

        final RadioButton one = (RadioButton) rv.findViewById(R.id.one);
        final RadioButton two = (RadioButton) rv.findViewById(R.id.two);

        fp.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                numberTextView.setText("Number of fingers");
                isFpKyc = true;
            }
        });

        iris.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                numberTextView.setText("Number of iris");
                isFpKyc = false;
            }
        });

        fp.setChecked(true);
        two.setChecked(true);

        FloatingActionButton fab = (FloatingActionButton) rv.findViewById(R.id.kyc);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (one.isChecked()) {
                    numberOffCapture = 1;
                } else if (two.isChecked()) {
                    numberOffCapture = 2;
                }
                kyc(view);
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

    public void kyc(View v) {
        if (TextUtils.isEmpty(aadhaarTextView.getText())) {
            showToast(
                    "Invalid Aadhaar Number. Please enter a valid Aadhaar Number",
                    Toast.LENGTH_LONG);
            return;
        }

        KycCaptureRequest kycCaptureRequest = new KycCaptureRequest();

        AuthCaptureRequest authCaptureRequest = new AuthCaptureRequest();
        authCaptureRequest.setAadhaar(aadhaarTextView.getText().toString().replaceAll("\\s", ""));
        authCaptureRequest.setModality(Modality.biometric);
        if (isFpKyc) {
            authCaptureRequest.setModalityType(ModalityType.fp);
            authCaptureRequest.setNumOffingersToCapture(numberOffCapture);
        } else {
            authCaptureRequest.setModalityType(ModalityType.iris);
            authCaptureRequest.setNumOfIrisToCapture(numberOffCapture);
        }
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

        Location loc = new Location();
        loc.setType(LocationType.pincode);
        loc.setPincode("560076");
        authCaptureRequest.setLocation(loc);

        kycCaptureRequest.setAuthCaptureRequest(authCaptureRequest);
        kycCaptureRequest.setConsent(ConsentType.Y);


        Intent i = new Intent();
        i = new Intent("com.aadhaarconnect.bridge.action.KYCCAPTURE");
        i.putExtra("REQUEST", GsonSerializerUtil.marshall(kycCaptureRequest));
        try {
            startActivityForResult(i, AADHAAR_CONNECT_KYC_REQUEST);
        } catch (Exception e) {
            Log.e("ERROR", e.getMessage());
        }
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode == Activity.RESULT_OK && requestCode == AADHAAR_CONNECT_KYC_REQUEST && data != null) {
            String responseStr = data.getStringExtra(AADHAAR_CONNECT_RESPONSE);
            kycCaptureData = new Gson().fromJson(responseStr, KycCaptureData.class);

            if (prefs.getAll().isEmpty()) {
                Log.d(LOG_TAG, "URL Prefs not set");
                ObservableRequests.get("https://ac.khoslalabs.com/hackgate/hackathon/kyc", kycCaptureData, ABSEvent.KYC);
            } else {
                Log.d(LOG_TAG, "Using set URL prefs");
                ObservableRequests.get(prefs.getString("serverHost", "https://ac.khoslalabs.com/hackgate/hackathon") + "/kyc", kycCaptureData, ABSEvent.KYC);

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
                case KYC:
                    KycResponse kycResponse = GsonSerializerUtil.unmarshal(event.getResponseString(), KycResponse.class);
                    if (kycResponse.isSuccess()) {
                        Intent i = new Intent(getActivity(), ResultActivity.class);
                        i.putExtra(RESULT_TYPE, KYC);
                        i.putExtra(KYCCAPTUREDATA, GsonSerializerUtil.marshall(kycCaptureData));
                        i.putExtra(KYCRESPONSE, GsonSerializerUtil.marshall(kycResponse));
                        startActivity(i);
                    } else {
                        AlertDialog alertDialog = new AlertDialog.Builder(getActivity()).create();
                        alertDialog.setTitle("Status");

                        String msg = "Kyc Status: " + (kycResponse.isSuccess() ? "success" : "fail")
                                + (null != kycResponse.getReferenceCode() ? "\nRefcode: " + kycResponse.getReferenceCode() : "")
                                + (null != kycResponse.getStatusCode() ? "\nStatusCode: " + kycResponse.getStatusCode() : "");
                        alertDialog.setMessage(msg);
                        alertDialog.setButton("OK", new DialogInterface.OnClickListener() {
                            public void onClick(DialogInterface dialog, int which) {
                                dialog.dismiss();
                            }
                        });

                        alertDialog.show();
                    }
                    break;
                default:
                    break;
            }
        } else {
            AlertDialog alertDialog = new AlertDialog.Builder(getActivity()).create();
            alertDialog.setTitle("Status");

            String msg = "Kyc Status: fail\n"
                    + ("Error, code is : " + event.getCode());
            alertDialog.setMessage(msg);
            alertDialog.setButton("OK", new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    dialog.dismiss();
                }
            });

            alertDialog.show();
        }
        EventBus.getDefault().removeStickyEvent(CompletionEvent.class);
    }
}

