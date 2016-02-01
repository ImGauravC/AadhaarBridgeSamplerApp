package com.aadhaarconnect.bridge.sampler;

import android.app.Activity;
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

import com.aadhaarconnect.bridge.capture.model.bfd.BfdCaptureData;
import com.aadhaarconnect.bridge.capture.model.bfd.BfdCaptureRequest;
import com.aadhaarconnect.bridge.capture.model.bfd.BfdType;
import com.aadhaarconnect.bridge.capture.model.common.Location;
import com.aadhaarconnect.bridge.capture.model.common.LocationType;
import com.aadhaarconnect.bridge.capture.model.common.request.CertificateType;
import com.aadhaarconnect.bridge.gateway.model.BfdResponse;
import com.aadhaarconnect.bridge.sampler.async.ObservableRequests;
import com.aadhaarconnect.bridge.sampler.events.ABSEvent;
import com.aadhaarconnect.bridge.sampler.events.CompletionEvent;
import com.aadhaarconnect.bridge.sampler.events.StartingEvent;
import com.aadhaarconnect.bridge.sampler.util.AadhaarNumberFormatter;
import com.aadhaarconnect.bridge.sampler.util.GsonSerializerUtil;
import com.support.android.designlibdemo.R;

import de.greenrobot.event.EventBus;

public class BfdFragment extends EventFragment implements Constants {
    public static final int AADHAAR_CONNECT_BFD_REQUEST = 1006;
    public static final String AADHAAR_CONNECT_RESPONSE = "RESPONSE";
    public static final String LOG_TAG = BfdFragment.class.getSimpleName();
    private EditText aadhaarTextView;
    private BfdCaptureData bfdCaptureData;
    private SharedPreferences prefs;

    private boolean isEditable = true;

    @Nullable
    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View rv = inflater.inflate(
                R.layout.bfd_view, container, false);

        aadhaarTextView = (EditText) rv.findViewById(R.id.aadhaarId);

        prefs = PreferenceManager.getDefaultSharedPreferences(getActivity());

        FloatingActionButton fab = (FloatingActionButton) rv.findViewById(R.id.bfd);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                authenticate(view);
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

        BfdCaptureRequest bfdCaptureRequest = new BfdCaptureRequest();
        bfdCaptureRequest.setBfdType(BfdType.SIX_FINGER);
        bfdCaptureRequest.setAadhaar(aadhaarTextView.getText().toString().replaceAll("\\s", ""));
        if(prefs.getAll().isEmpty()) {
            Log.d(LOG_TAG, "Environment Prefs not set");
            bfdCaptureRequest.setCertificateType(CertificateType.preprod);
        } else {
            Log.d(LOG_TAG, "Using set Environment prefs");
            String env = prefs.getString("environment", PREPROD);
            if (TextUtils.equals(env, PREPROD)) {
                bfdCaptureRequest.setCertificateType(CertificateType.preprod);
            } else if (TextUtils.equals(env, PROD)) {
                bfdCaptureRequest.setCertificateType(CertificateType.prod);
            }
        }

        Location loc = new Location();
        loc.setType(LocationType.pincode);
        loc.setPincode("560076");
        bfdCaptureRequest.setLocation(loc);

        Intent i = new Intent();
        i = new Intent("com.aadhaarconnect.bridge.action.BFDCAPTURE");
        i.putExtra("REQUEST", GsonSerializerUtil.marshall(bfdCaptureRequest));
        try {
            startActivityForResult(i, AADHAAR_CONNECT_BFD_REQUEST);
        } catch (Exception e) {
            Log.e("ERROR", e.getMessage());
        }
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode == Activity.RESULT_OK && requestCode == AADHAAR_CONNECT_BFD_REQUEST && data != null) {
            String responseStr = data.getStringExtra(AADHAAR_CONNECT_RESPONSE);
            bfdCaptureData = GsonSerializerUtil.unmarshal(responseStr, BfdCaptureData.class);

            if(prefs.getAll().isEmpty()) {
                Log.d(LOG_TAG, "URL Prefs not set");
                ObservableRequests.get("https://ac.khoslalabs.com/hackgate/hackathon/bfd", bfdCaptureData, ABSEvent.BFD);
            } else {
                Log.d(LOG_TAG, "Using set URL prefs");
                ObservableRequests.get(prefs.getString("serverHost","https://ac.khoslalabs.com/hackgate/hackathon") + "/bfd", bfdCaptureData, ABSEvent.BFD);
            }
        }
    }

    private void showToast(String text, int duration) {
        Toast toast = Toast.makeText(this.getActivity(), text, duration);
        toast.show();
    }

    public void onEventMainThread(StartingEvent event) {
        showProgressDialog();
        setProgressMessage(R.string.progress_message);
        EventBus.getDefault().removeStickyEvent(StartingEvent.class);
    }

    public void onEventMainThread(CompletionEvent event) {
        dismissProgressDialog();

        if (event.WasEventASuccess()) {
            switch (event.getEvent()) {
                case BFD:
                    BfdResponse bfdResponse = GsonSerializerUtil.unmarshal(event.getResponseString(), BfdResponse.class);
                    Intent i = new Intent(getActivity(), ResultActivity.class);
                    i.putExtra(RESULT_TYPE, AUTH);
                    i.putExtra(BFDCAPTUREDATA, GsonSerializerUtil.marshall(bfdCaptureData));
                    i.putExtra(BFDRESPONSE, GsonSerializerUtil.marshall(bfdResponse));
//                    startActivity(i);
                    break;
                default:
                    break;
            }
        } else {
            Toast.makeText(getActivity(), "Error, code is : " + event.getCode(), Toast.LENGTH_LONG).show();
        }
        EventBus.getDefault().removeStickyEvent(CompletionEvent.class);
    }
}

