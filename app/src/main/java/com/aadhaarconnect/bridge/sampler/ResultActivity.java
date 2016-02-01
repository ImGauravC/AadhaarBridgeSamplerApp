package com.aadhaarconnect.bridge.sampler;

import android.app.FragmentManager;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;

import com.support.android.designlibdemo.R;

public class ResultActivity extends AppCompatActivity implements Constants {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_result);

        String requestType = getIntent().getStringExtra(RESULT_TYPE);

        if(TextUtils.equals(requestType, AUTH)) {
            AuthDisplayFragment displayFragment = AuthDisplayFragment.newInstance();
            //TODO : pass the arguments such result msg and auth ref code
            FragmentManager fragmentManager = getFragmentManager();
            fragmentManager.beginTransaction()
                    .replace(R.id.content_frame, displayFragment).commit();
        } else if(TextUtils.equals(requestType, KYC)) {
            KycDisplayFragment kycDisplayFragment = KycDisplayFragment.newInstance();
            FragmentManager fragmentManager = getFragmentManager();
            fragmentManager.beginTransaction()
                    .replace(R.id.content_frame, kycDisplayFragment).commit();
        }
    }
}
