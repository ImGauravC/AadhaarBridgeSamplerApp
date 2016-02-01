package com.aadhaarconnect.bridge.sampler;

import android.os.Bundle;
import android.preference.PreferenceActivity;
import android.text.TextUtils;

import com.support.android.designlibdemo.R;

public class AppSettingActivity extends PreferenceActivity {
    public static final String TYPE_KEY = "TYPE";
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String type = getIntent().getStringExtra(TYPE_KEY);

        addPreferencesFromResource(R.xml.app_preferences);
        if(!TextUtils.isEmpty(type) && "INITIALIZE".equalsIgnoreCase(type)) {
            this.finish();
        }
    }
}